require('dotenv').config();
const express = require('express');
const cors = require('cors');
const dns = require('dns');
const { exec } = require('child_process');
const { URL } = require('url');
const path = require('path');
const fs = require('fs').promises;
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('./models/User'); // Import the User model

const app = express();
const port = process.env.PORT || 3000;

// MongoDB connection
const mongoURI = process.env.MONGO_URI;
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// Middleware
app.use(cors());
app.use(express.static('public'));
app.use(express.json());

// Create logs directory if it doesn't exist
const ensureLogsDirectory = async () => {
  const logsDir = path.join(__dirname, 'logs');
  try {
    await fs.access(logsDir);
  } catch (error) {
    await fs.mkdir(logsDir);
  }
  return logsDir;
};

// Logger
const logActivity = async (type, data) => {
  try {
    const logsDir = await ensureLogsDirectory();
    const date = new Date();
    const logFile = path.join(logsDir, `ping-log-${date.toISOString().split('T')[0]}.log`);
    
    const logEntry = {
      timestamp: date.toISOString(),
      type,
      ...data
    };
    
    // Append to log file
    await fs.appendFile(
      logFile,
      JSON.stringify(logEntry) + '\n',
      { encoding: 'utf8' }
    );
  } catch (err) {
    console.error('Logging error:', err);
  }
};

// Utility to check if input is IP or needs HTTP prefix
function normalizeUrl(input) {
  if (/^https?:\/\//.test(input)) {
    return input;
  }
  return 'http://' + input;
}

// Parse ping results based on platform
function parsePingResults(stdout) {
  const isWin = process.platform === 'win32';
  let data = {
    sent: null,
    received: null,
    packetLoss: null,
    minTime: null,
    maxTime: null,
    avgTime: null
  };
  
  // Extract packet loss
  const packetLossRegex = isWin 
    ? /Lost = (\d+) \((\d+)% loss\)/i
    : /(\d+)% packet loss/i;
    
  const packetLossMatch = stdout.match(packetLossRegex);
  
  if (packetLossMatch) {
    data.packetLoss = isWin 
      ? parseInt(packetLossMatch[2]) 
      : parseInt(packetLossMatch[1]);
  }
  
  // Extract time statistics
  const timeRegex = isWin
    ? /Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms/i
    : /min\/avg\/max(?:\/mdev)? = ([\d.]+)\/([\d.]+)\/([\d.]+)/i;
    
  const timeMatch = stdout.match(timeRegex);
  
  if (timeMatch) {
    if (isWin) {
      data.minTime = parseInt(timeMatch[1]);
      data.maxTime = parseInt(timeMatch[2]);
      data.avgTime = parseInt(timeMatch[3]);
    } else {
      data.minTime = parseFloat(timeMatch[1]);
      data.maxTime = parseFloat(timeMatch[3]);
      data.avgTime = parseFloat(timeMatch[2]);
    }
  }
  
  // Extract sent/received packets
  const packetsRegex = isWin
    ? /Sent = (\d+), Received = (\d+)/i
    : /(\d+) packets transmitted, (\d+) (?:packets )?received/i;
    
  const packetsMatch = stdout.match(packetsRegex);
  
  if (packetsMatch) {
    data.sent = parseInt(packetsMatch[1]);
    data.received = parseInt(packetsMatch[2]);
  }
  
  return data;
}

// Ping command based on platform
const isWin = process.platform === 'win32';
const pingCmd = (host, count = 4) => isWin 
  ? `ping -n ${count} ${host}` 
  : `ping -c ${count} ${host}`;

// Routes
app.get('/ping', async (req, res) => {
  let target = req.query.url;
  const count = parseInt(req.query.count) || 4;
  
  if (!target) {
    return res.status(400).json({ error: 'No URL provided' });
  }

  try {
    const url = new URL(normalizeUrl(target));
    const hostname = url.hostname;
    
    // Log request
    await logActivity('ping_request', {
      target: hostname,
      ip: req.ip,
      userAgent: req.get('user-agent'),
    });

    exec(pingCmd(hostname, count), (error, stdout, stderr) => {
      console.log('Ping stdout:', stdout); // Log the raw output
      console.log('Ping stderr:', stderr); // Log any errors
      console.log('Ping error:', error);   // Log the error object

      const pingData = parsePingResults(stdout);
      console.log('Parsed Ping Data:', pingData); // Log the parsed data

      // Check if packet loss is valid
      if (pingData.packetLoss === null) {
        console.error('Ping command error:', stderr || error?.message || 'Unknown error');
        return res.json({ 
          status: 'down', 
          hostname,
          error: stderr || error?.message || 'Failed to ping host'
        });
      }

      // Determine status based on packet loss
      let status = 'unknown';
      if (pingData.packetLoss === 0) status = 'green';
      else if (pingData.packetLoss <= 50) status = 'yellow';
      else status = 'red';

      const result = {
        status: pingData.packetLoss < 100 ? 'up' : 'down',
        hostname,
        packetLoss: pingData.packetLoss,
        responseTime: pingData.avgTime,
        stats: {
          min: pingData.minTime,
          max: pingData.maxTime,
          avg: pingData.avgTime,
          sent: pingData.sent,
          received: pingData.received
        },
        dot: status,
        timestamp: new Date().toISOString(),
        raw: stdout
      };

      res.json(result);
    });
  } catch (err) {
    console.error('Invalid URL:', err.message);
    
    // Log error
    logActivity('ping_error', {
      target: req.query.url,
      error: err.message
    });
    
    return res.status(400).json({ error: 'Invalid URL' });
  }
});

// For batch processing multiple sites
app.post('/ping-batch', async (req, res) => {
  const { urls } = req.body;
  
  if (!urls || !Array.isArray(urls)) {
    return res.status(400).json({ error: 'Invalid request format' });
  }
  
  // To prevent DoS, limit the number of URLs
  const MAX_URLS = 20;
  const processUrls = urls.slice(0, MAX_URLS);
  
  try {
    // Log batch request
    await logActivity('batch_request', {
      count: processUrls.length,
      ip: req.ip
    });
    
    // Process one by one to not overwhelm the system
    const results = {};
    
    for (const url of processUrls) {
      // We'll reuse the logic but wrap it in a promise
      results[url] = await new Promise((resolve) => {
        try {
          const parsedUrl = new URL(normalizeUrl(url));
          const hostname = parsedUrl.hostname;
          
          exec(pingCmd(hostname), (error, stdout, stderr) => {
            if (error) {
              resolve({ 
                status: 'down', 
                hostname,
                error: stderr || error.message 
              });
              return;
            }
            
            const pingData = parsePingResults(stdout);
            
            let status = 'unknown';
            if (pingData.packetLoss !== null) {
              if (pingData.packetLoss === 0) status = 'green';
              else if (pingData.packetLoss <= 50) status = 'yellow';
              else status = 'red';
            }
            
            resolve({
              status: pingData.packetLoss < 100 ? 'up' : 'down',
              hostname,
              packetLoss: pingData.packetLoss,
              responseTime: pingData.avgTime,
              stats: {
                min: pingData.minTime,
                max: pingData.maxTime,
                avg: pingData.avgTime
              },
              dot: status,
              timestamp: new Date().toISOString()
            });
          });
        } catch (err) {
          resolve({ status: 'error', error: 'Invalid URL' });
        }
      });
    }
    
    res.json(results);
  } catch (err) {
    console.error('Batch processing error:', err);
    
    // Log error
    logActivity('batch_error', {
      error: err.message
    });
    
    res.status(500).json({ error: 'Server error' });
  }
});

// Stats endpoint
app.get('/stats', async (req, res) => {
  try {
    const logsDir = await ensureLogsDirectory();
    const date = req.query.date || new Date().toISOString().split('T')[0];
    const logFile = path.join(logsDir, `ping-log-${date}.log`);
    
    try {
      const logContent = await fs.readFile(logFile, 'utf8');
      const logs = logContent.split('\n')
        .filter(line => line.trim())
        .map(line => JSON.parse(line));
      
      // Calculate stats
      const stats = {
        totalRequests: logs.filter(log => log.type === 'ping_request').length,
        successRate: 0,
        avgResponseTime: 0,
        mostPinged: {},
        requestsByHour: Array(24).fill(0)
      };
      
      // Process successful pings
      const successfulPings = logs.filter(log => log.type === 'ping_success');
      
      if (successfulPings.length > 0) {
        stats.successRate = successfulPings.length / logs.filter(log => 
          log.type === 'ping_success' || log.type === 'ping_failure'
        ).length * 100;
        
        // Calculate average response time
        const totalResponseTime = successfulPings.reduce((sum, log) => 
          sum + (log.responseTime || 0), 0);
        stats.avgResponseTime = totalResponseTime / successfulPings.length;
        
        // Find most pinged targets
        const targetCounts = {};
        logs.filter(log => log.type === 'ping_request').forEach(log => {
          if (!targetCounts[log.target]) targetCounts[log.target] = 0;
          targetCounts[log.target]++;
        });
        
        stats.mostPinged = Object.entries(targetCounts)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5)
          .reduce((obj, [target, count]) => {
            obj[target] = count;
            return obj;
          }, {});
          
        // Group by hour
        logs.filter(log => log.type === 'ping_request').forEach(log => {
          const hour = new Date(log.timestamp).getHours();
          stats.requestsByHour[hour]++;
        });
      }
      
      res.json(stats);
    } catch (error) {
      // No log file found or other error
      res.json({
        totalRequests: 0,
        successRate: 0,
        avgResponseTime: 0,
        mostPinged: {},
        requestsByHour: Array(24).fill(0)
      });
    }
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Failed to retrieve stats' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// Register a new user
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error registering user' });
  }
});

// Login a user
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // For simplicity, return user data (you can use JWT for secure sessions)
    res.json({ message: 'Login successful', user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error logging in' });
  }
});

// Save website data for a user
app.post('/save-website', async (req, res) => {
  const { username, website } = req.body;
  if (!username || !website) {
    return res.status(400).json({ error: 'Username and website data are required' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.websites.push(website);
    await user.save();
    res.json({ message: 'Website saved successfully', websites: user.websites });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error saving website' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(port, () => {
  console.log(`✅ Ping Checker running at http://localhost:${port}`);
  console.log(`Platform: ${process.platform}, Using ping command: ${pingCmd('example.com')}`);
});