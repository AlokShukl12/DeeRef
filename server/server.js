const express = require('express');
const http = require('http');
const cors = require('cors');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { Server } = require('socket.io');

dotenv.config();

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/mini-chat';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const configuredOrigins = (process.env.CLIENT_ORIGINS || process.env.CLIENT_ORIGIN || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);
const defaultDevOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:4173',
  'http://127.0.0.1:4173',
  'http://localhost:3000',
  'http://127.0.0.1:3000',
];
const allowedOrigins = configuredOrigins.length ? configuredOrigins : defaultDevOrigins;
const allowAllOrigins = configuredOrigins.includes('*') || process.env.NODE_ENV !== 'production';
const corsOptions = allowAllOrigins
  ? { origin: true, credentials: true } // echo any origin in dev or when explicitly allowed
  : {
      origin: (origin, callback) => {
        if (!origin) return callback(null, true); // allow tools/curl with no origin header
        if (allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error(`Origin not allowed by CORS: ${origin}`));
      },
      credentials: true,
    };

const io = new Server(server, {
  cors: {
    origin: allowAllOrigins ? '*' : allowedOrigins,
    methods: ['GET', 'POST'],
  },
});

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

mongoose
  .connect(MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

const userSchema = new mongoose.Schema(
  {
    username: { type: String, unique: true, required: true, trim: true },
    passwordHash: { type: String, required: true },
  },
  { timestamps: true }
);

const channelSchema = new mongoose.Schema(
  {
    name: { type: String, unique: true, required: true, trim: true },
    members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  },
  { timestamps: true }
);

const messageSchema = new mongoose.Schema(
  {
    channel: { type: mongoose.Schema.Types.ObjectId, ref: 'Channel', required: true, index: true },
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: { type: String, required: true, trim: true },
  },
  { timestamps: true }
);

messageSchema.index({ channel: 1, createdAt: -1 });

const User = mongoose.model('User', userSchema);
const Channel = mongoose.model('Channel', channelSchema);
const Message = mongoose.model('Message', messageSchema);

function generateToken(user) {
  return jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'Unauthorized' });
  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    return next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Username and password required' });
    const existing = await User.findOne({ username: username.trim().toLowerCase() });
    if (existing) return res.status(400).json({ message: 'Username already taken' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ username: username.trim().toLowerCase(), passwordHash });
    const token = generateToken(user);
    res.json({ user: { _id: user._id, username: user.username }, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to register' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username: username?.trim().toLowerCase() });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    const valid = await bcrypt.compare(password || '', user.passwordHash);
    if (!valid) return res.status(400).json({ message: 'Invalid credentials' });
    const token = generateToken(user);
    res.json({ user: { _id: user._id, username: user.username }, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to login' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.id).select('_id username');
  if (!user) return res.status(404).json({ message: 'User not found' });
  res.json({ user });
});

app.get('/api/channels', authMiddleware, async (req, res) => {
  const channels = await Channel.find().lean();
  const mapped = channels.map((c) => ({
    _id: c._id,
    name: c.name,
    membersCount: c.members.length,
    isMember: c.members.some((id) => id.toString() === req.user.id),
  }));
  res.json({ channels: mapped });
});

app.post('/api/channels', authMiddleware, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ message: 'Channel name required' });
    const existing = await Channel.findOne({ name: name.trim().toLowerCase() });
    if (existing) return res.status(400).json({ message: 'Channel already exists' });
    const channel = await Channel.create({
      name: name.trim().toLowerCase(),
      members: [req.user.id],
      createdBy: req.user.id,
    });
    res.json({ channel: { _id: channel._id, name: channel.name, membersCount: 1, isMember: true } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Failed to create channel' });
  }
});

app.post('/api/channels/:id/join', authMiddleware, async (req, res) => {
  const channel = await Channel.findById(req.params.id);
  if (!channel) return res.status(404).json({ message: 'Channel not found' });
  const alreadyMember = channel.members.some((id) => id.toString() === req.user.id);
  if (!alreadyMember) {
    channel.members.push(req.user.id);
    await channel.save();
  }
  res.json({ success: true });
});

app.post('/api/channels/:id/leave', authMiddleware, async (req, res) => {
  const channel = await Channel.findById(req.params.id);
  if (!channel) return res.status(404).json({ message: 'Channel not found' });
  channel.members = channel.members.filter((id) => id.toString() !== req.user.id);
  await channel.save();
  res.json({ success: true });
});

app.get('/api/channels/:id/messages', authMiddleware, async (req, res) => {
  const { limit = 20, before } = req.query;
  const parsedLimit = Math.min(parseInt(limit, 10) || 20, 50);
  const beforeDate = before ? new Date(before) : new Date();

  const channel = await Channel.findById(req.params.id);
  if (!channel) return res.status(404).json({ message: 'Channel not found' });
  const isMember = channel.members.some((id) => id.toString() === req.user.id);
  if (!isMember) return res.status(403).json({ message: 'Join channel to view messages' });

  const messages = await Message.find({ channel: req.params.id, createdAt: { $lt: beforeDate } })
    .sort({ createdAt: -1 })
    .limit(parsedLimit)
    .populate('sender', 'username')
    .lean();

  const hasMore = messages.length === parsedLimit;
  const nextCursor = hasMore ? messages[messages.length - 1].createdAt.toISOString() : null;
  res.json({ messages: messages.reverse(), nextCursor });
});

const onlineUsers = new Map(); // userId -> { username, count }

function broadcastPresence() {
  const list = Array.from(onlineUsers.entries()).map(([id, entry]) => ({
    _id: id,
    username: entry.username,
  }));
  io.emit('presence:update', list);
}

function formatMessage(msg) {
  return {
    _id: msg._id,
    channel: msg.channel.toString(),
    content: msg.content,
    createdAt: msg.createdAt,
    sender: { _id: msg.sender._id?.toString?.() || msg.sender.toString(), username: msg.sender.username },
  };
}

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('Authentication required'));
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    socket.user = payload;
    return next();
  } catch (err) {
    return next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  const userId = socket.user.id;
  const username = socket.user.username;
  const existing = onlineUsers.get(userId) || { username, count: 0 };
  onlineUsers.set(userId, { username, count: existing.count + 1 });
  broadcastPresence();

  socket.on('joinChannel', (channelId) => {
    if (!channelId) return;
    socket.join(`channel:${channelId}`);
  });

  socket.on('leaveChannel', (channelId) => {
    if (!channelId) return;
    socket.leave(`channel:${channelId}`);
  });

  socket.on('message:create', async ({ channelId, content }, callback) => {
    try {
      if (!channelId || !content?.trim()) return callback?.({ error: 'Message content required' });
      const channel = await Channel.findById(channelId);
      if (!channel) return callback?.({ error: 'Channel not found' });

      const isMember = channel.members.some((id) => id.toString() === userId);
      if (!isMember) {
        channel.members.push(userId);
        await channel.save();
      }

      const message = await Message.create({ channel: channelId, sender: userId, content: content.trim() });
      const populated = await message.populate('sender', 'username');
      io.to(`channel:${channelId}`).emit('message:new', formatMessage(populated));
      callback?.({ success: true });
    } catch (err) {
      console.error('Failed to create message', err);
      callback?.({ error: 'Failed to send message' });
    }
  });

  socket.on('disconnect', () => {
    const entry = onlineUsers.get(userId);
    if (!entry) return;
    if (entry.count <= 1) onlineUsers.delete(userId);
    else onlineUsers.set(userId, { username: entry.username, count: entry.count - 1 });
    broadcastPresence();
  });
});

app.get('/health', (_req, res) => res.send('ok'));

server.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
