const { spawn } = require("child_process");
const fs = require("fs");
const fsPromises = fs.promises;
const path = require("path");
const os = require("os");
const https = require("https");
const { RateLimiterMemory } = require('rate-limiter-flexible');

let config;
let trafficSummary = {
  uniqueIps: new Set(),  
  totalTraffic: 0,
  ipTraffic: {},
  blockedIps: new Set(),
  packetCounts: { 
    SYN: 0, UDP: 0, ICMP: 0, TCP: 0, DNS: 0, NTP: 0, SSH: 0, GRE: 0, ESP: 0, 
    RST: 0, FIN: 0, PSH: 0, ACK: 0, URG: 0 
  },
  maliciousIps: new Set(),
};

let isAttackDetected = false;

const MAX_REQUESTS_PER_SECOND = 10;
const MAX_CONNECTIONS_PER_IP = 20;
const BAN_TIME = 60 * 1000;
const IP_BAN_MAP = new Map();
const IP_REQUEST_MAP = new Map();
const BLOCKED_USER_AGENTS = new Set();
const BLACKLISTED_IPS = new Set();
const LOCAL_IP = '127.0.0.1';
const SSL_CERTIFICATE_PATH = 'cert.pem'; 
const SSL_PRIVATE_KEY_PATH = 'private-key.pem';

const rateLimiter = new RateLimiterMemory({
  points: MAX_REQUESTS_PER_SECOND,
  duration: 1,
});

const ACCESS_LOG_PATH = 'assets/access-logs.txt';
const USER_ACTIVITY_LOG_PATH = 'assets/user-activity-logs.txt';
const CONNECTION_LOG_PATH = 'assets/connection-logs.txt';

const blockSettingFile = 'assets/block_setting.txt';
fs.readFile(blockSettingFile, 'utf8', (err, data) => {
  if (err) {
    console.error(`Error reading block_setting.txt file: ${err}`);
    return;
  }
  const ipsToBlock = data.split('\n');
  ipsToBlock.forEach((ip) => {
    ip = ip.trim();
    if (ip) {
      BLACKLISTED_IPS.add(ip);
    }
  });
});

const logUserActivity = (clientIP, requestPath, userAgent) => {
  const logMessage = `User ${clientIP} accessed ${requestPath} using ${userAgent}\n`;
  fs.appendFileSync(USER_ACTIVITY_LOG_PATH, logMessage);
};

const logConnection = (clientIP) => {
  const logMessage = `Connection from IP => ${clientIP}\n`;
  fs.appendFileSync(CONNECTION_LOG_PATH, logMessage);
};

const blockUserAgent = (userAgent) => {
  if (userAgent && (userAgent.toLowerCase().includes('ddos') || userAgent.toLowerCase().includes('thread'))) {
    BLOCKED_USER_AGENTS.add(userAgent);
  }
};

const handleFloodProtection = (clientIP) => {
  if (isLocalConnection(clientIP)) {
    return false;
  }
  const currentTime = Date.now();
  const recentRequests = IP_REQUEST_MAP.get(clientIP) || [];

  IP_REQUEST_MAP.set(
    clientIP,
    recentRequests.filter((requestTime) => currentTime - requestTime <= BAN_TIME)
  );

  if (recentRequests.length >= MAX_REQUESTS_PER_SECOND) {
    return true;  // IP is blocked due to flood protection
  }

  recentRequests.push(currentTime);
  IP_REQUEST_MAP.set(clientIP, recentRequests);

  return false;
};

const isLocalConnection = (clientIP) => {
  return clientIP === LOCAL_IP;
};

const analyzeLiveTraffic = (interfaceName) => {
  const tshark = spawn("tshark", [
    "-i", interfaceName,
    "-T", "fields",
    "-Q",
    "-e", "ip.src",
    "-e", "data.text",
    "-e", "frame.len",
    "-e", "tcp.flags",
    "-e", "udp.port",
    "-e", "icmp.type",
  ]);

  tshark.stdout.on("data", (data) => {
    const lines = data.toString().trim().split("\n");
    lines.forEach((line) => {
      const parts = line.split("\t");

      if (!parts[0]) return; // Ignore empty lines
      const ip = parts[0];
      const frameLen = parseInt(parts[2], 10) || 0;

      // Update traffic for the current IP
      if (!trafficSummary.ipTraffic[ip]) {
        trafficSummary.ipTraffic[ip] = [];
        trafficSummary.uniqueIps.add(ip);
      }

      trafficSummary.ipTraffic[ip].push(frameLen);
      trafficSummary.totalTraffic += frameLen;

      // Increment packet counts (to use in dashboard display)
      if (parts[3]) {
        if (parts[3].includes("SYN")) trafficSummary.packetCounts.SYN++;
        if (parts[3].includes("UDP")) trafficSummary.packetCounts.UDP++;
        if (parts[3].includes("ICMP")) trafficSummary.packetCounts.ICMP++;
        if (parts[3].includes("TCP")) trafficSummary.packetCounts.TCP++;
        if (parts[3].includes("DNS")) trafficSummary.packetCounts.DNS++;
        if (parts[3].includes("NTP")) trafficSummary.packetCounts.NTP++;
        if (parts[3].includes("SSH")) trafficSummary.packetCounts.SSH++;
        if (parts[3].includes("GRE")) trafficSummary.packetCounts.GRE++;
        if (parts[3].includes("ESP")) trafficSummary.packetCounts.ESP++;
        if (parts[3].includes("RST")) trafficSummary.packetCounts.RST++;
        if (parts[3].includes("FIN")) trafficSummary.packetCounts.FIN++;
        if (parts[3].includes("PSH")) trafficSummary.packetCounts.PSH++;
        if (parts[3].includes("ACK")) trafficSummary.packetCounts.ACK++;
        if (parts[3].includes("URG")) trafficSummary.packetCounts.URG++;
      }

      // Check if the IP is flooding or not
      const isFlooded = handleFloodProtection(ip);
      if (isFlooded) return;  // Skip processing for flooded IPs

      // Check if traffic exceeds threshold for blocking
      const totalIpTraffic = trafficSummary.ipTraffic[ip].reduce((a, b) => a + b, 0);
      if (totalIpTraffic > config.thresholds.MB && !trafficSummary.blockedIps.has(ip)) {
        trafficSummary.maliciousIps.add(ip);
        blockIp(ip);  // Block malicious IP
      }
    });
  });

  // Error handling for tshark process
  tshark.stderr.on("data", (err) => {
    console.error("Error with tshark: ", err.toString());
  });

  tshark.on("close", (code) => {
    if (code !== 0) {
      console.error(`tshark process exited with code ${code}`);
    }
  });
};

const checkMaliciousActivity = () => {
  // If there are any malicious IPs detected, return true
  return trafficSummary.maliciousIps.size > 0;
};

const displayDashboard = () => {
  console.clear();

  let displayDetails = `
                    SERVER MONITORING DASHBOARD
   ------------------------------------------------------------
    Interface           : ${config.interface}
    Server IP           : ${config.serverIp || "N/A"}
    Server Port         : ${config.serverPort || "N/A"}
    CPU Model           : ${os.cpus()[0].model}
    CPU Cores           : ${os.cpus().length}
    Memory Usage        : ${(os.freemem() / (1024 ** 3)).toFixed(2)} GB free / ${(os.totalmem() / (1024 ** 3)).toFixed(2)} GB total
    Total Traffic (MB)  : ${(trafficSummary.totalTraffic / (1024 * 1024)).toFixed(2)}
    Unique IPs Monitored: ${trafficSummary.uniqueIps.size}
    Malicious Activity  : ${checkMaliciousActivity() ? "YES" : "NO"}
   ------------------------------------------------------------
  `;

  console.log(displayDetails);
};



const blockIp = (ip) => {
  if (trafficSummary.blockedIps.has(ip) || config.whitelistedIps.includes(ip)) {
    return;
  }

  // Clean up the IP address (remove leading or trailing dots)
  ip = ip.trim().replace(/^\.|\.$/g, '');

  // Split the IP into octets
  const octets = ip.split('.');

  // If there are fewer than 4 octets, pad the address with `.0` to make it valid
  while (octets.length < 4) {
    octets.push('0');
  }

  // Rebuild the IP address
  const validIp = octets.slice(0, 4).join('.');

  // Check if the transformed IP is valid (it should be now)
  const isValidIp = validIp.split('.').every(octet => {
    const parsedOctet = parseInt(octet, 10);
    return parsedOctet >= 0 && parsedOctet <= 255 && !isNaN(parsedOctet);
  });

  if (!isValidIp) {
    console.error(`Invalid IP address format: ${validIp}`);
    return;
  }

  const iptables = spawn("sudo", ["iptables", "-A", "INPUT", "-s", validIp, "-j", "DROP"]);

  iptables.on("close", (code) => {
    if (code === 0) {
      trafficSummary.blockedIps.add(validIp);
    } else {
      console.error(`Failed to block IP: ${validIp}`);
    }
  });
};

const sendDiscordAlert = (alertDetails) => {
  const { webhookUrl, messageTemplate } = config.discord;
  const message = {
    content: "",
    embeds: [
      {
        title: messageTemplate.title,
        description: `🚨 Malicious traffic detected exceeding thresholds.\n\n${alertDetails}`,
        color: 16711680,
        image: { url: messageTemplate.image },
        timestamp: new Date().toISOString(),
      },
    ],
  };

  const webhookUrlParsed = new URL(webhookUrl);

  const requestOptions = {
    hostname: webhookUrlParsed.hostname,
    path: webhookUrlParsed.pathname + webhookUrlParsed.search,
    method: "POST",
    headers: { "Content-Type": "application/json" },
  };

  const req = https.request(requestOptions, (res) => {
    if (res.statusCode !== 204) {
      console.error(`Webhook failed with status code: ${res.statusCode}`);
    }
  });

  req.on("error", (error) => {
    console.error("Error sending webhook:", error.message);
  });

  req.write(JSON.stringify(message));
  req.end();
};

const loadConfig = async () => {
  try {
    const configPath = path.join(__dirname, "assets", "config.json");
    const configFile = await fsPromises.readFile(configPath, "utf8");
    return JSON.parse(configFile);
  } catch (error) {
    console.error("Failed to load config file:", error);
    process.exit(1);
  }
};

const generateAlertMessage = () => {
  let alertDetails = "";

  Object.entries(trafficSummary.packetCounts).forEach(([key, value]) => {
    const threshold = config.thresholds[key];
    if (value > threshold) {
      alertDetails += `${key}: ${value} (Threshold: ${threshold})\n`;
    }
  });

  if (trafficSummary.totalTraffic > config.thresholds.MB) {
    alertDetails += `Total Traffic: ${trafficSummary.totalTraffic.toFixed(2)} MB (Threshold: ${config.thresholds.MB} MB)\n`;
  }

  return alertDetails.trim();
};

const resetTrafficData = () => {
  trafficSummary.ipTraffic = {};
  trafficSummary.totalTraffic = 0;
  for (const key in trafficSummary.packetCounts) {
    trafficSummary.packetCounts[key] = 0;
  }
  trafficSummary.maliciousIps.clear();
};

const calculateCurrentTraffic = () => {
  return Object.values(trafficSummary.ipTraffic).reduce((a, b) => a + b, 0);
};

const checkTrafficThresholds = () => {
  const currentTraffic = calculateCurrentTraffic();

  // Check if current traffic exceeds threshold
  if (currentTraffic > config.thresholds.MB) {
    return true;
  }

  const packetCountsExceeded = Object.entries(trafficSummary.packetCounts).some(
    ([key, value]) => value > (config.thresholds[key] || 0)
  );

  return packetCountsExceeded;
};


const startRefreshingTable = () => {
  setInterval(() => {
    // Refresh the dashboard every 5 seconds
    const attackDetected = checkTrafficThresholds();

    if (attackDetected !== isAttackDetected) {
      isAttackDetected = attackDetected;

      if (isAttackDetected) {
        const alertDetails = generateAlertMessage();
        sendDiscordAlert(alertDetails);  // Send alert when attack detected
      } else {
        console.log("Traffic levels back to normal. Resetting traffic data.");
        resetTrafficData();  // Reset data once attack is no longer detected
      }
    }

    // Always reset traffic data when attack is not detected
    if (!isAttackDetected) {
      resetTrafficData();
    }

    displayDashboard();  // Display updated dashboard
  }, 5000);  // Refresh every 5 seconds
};


(async () => {
  config = await loadConfig();

  startRefreshingTable();
  analyzeLiveTraffic("eth0");
})();
