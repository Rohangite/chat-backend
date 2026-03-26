const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
});

// ─── CONFIG ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "chatapp_secret_2025";
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/chatapp";

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use("/uploads", express.static("uploads"));
fs.mkdirSync("uploads", { recursive: true });

// ─── DATABASE ─────────────────────────────────────────────────────────────────
mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.log("⚠️  MongoDB not connected (running in demo mode):", err.message));

// ─── MODELS ───────────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, trim: true },
  email:    { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  is_online: { type: Boolean, default: false },
  last_seen: { type: Date, default: Date.now },
  socket_id: { type: String, default: null },
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
  sender_id:   { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  receiver_id: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  text:        { type: String, default: "" },
  image_url:   { type: String, default: null },
  status:      { type: String, enum: ["sent", "delivered", "read"], default: "sent" },
  reactions:   [{ emoji: String, from: mongoose.Schema.Types.ObjectId }],
  deleted:     { type: Boolean, default: false },
}, { timestamps: true });

const User    = mongoose.model("User", userSchema);
const Message = mongoose.model("Message", messageSchema);

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
};

// ─── IMAGE UPLOAD ─────────────────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename:    (req, file, cb) => cb(null, `${Date.now()}-${file.originalname.replace(/\s/g, "_")}`),
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) cb(null, true);
    else cb(new Error("Only image files allowed"));
  },
});

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────
app.post("/api/auth/register", async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: "All fields required" });
  if (password.length < 6)
    return res.status(400).json({ error: "Password too short (min 6 chars)" });

  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ error: "Email already registered" });

    const hashed = await bcrypt.hash(password, 12);
    const user = await User.create({ username, email, password: hashed });
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "30d" });

    res.status(201).json({
      token,
      user: { _id: user._id, username: user.username, email: user.email, is_online: false },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "30d" });

    res.json({
      token,
      user: { _id: user._id, username: user.username, email: user.email, is_online: user.is_online },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── USER ROUTES ──────────────────────────────────────────────────────────────
app.get("/api/users", async (req, res) => {
  try {
    const users = await User.find().select("-password");
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/users/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password");
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── MESSAGE ROUTES ───────────────────────────────────────────────────────────
app.get("/api/messages/:userId", authMiddleware, async (req, res) => {
  try {
    const messages = await Message.find({
      $or: [
        { sender_id: req.user.userId, receiver_id: req.params.userId },
        { sender_id: req.params.userId, receiver_id: req.user.userId },
      ],
    }).sort({ createdAt: 1 }).limit(100);

    // Mark as delivered
    await Message.updateMany(
      { sender_id: req.params.userId, receiver_id: req.user.userId, status: "sent" },
      { status: "delivered" }
    );

    res.json(messages);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/messages/:messageId", authMiddleware, async (req, res) => {
  try {
    const msg = await Message.findById(req.params.messageId);
    if (!msg) return res.status(404).json({ error: "Message not found" });
    if (msg.sender_id.toString() !== req.user.userId)
      return res.status(403).json({ error: "Not authorized" });

    await Message.findByIdAndUpdate(req.params.messageId, { deleted: true, text: "This message was deleted" });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── IMAGE UPLOAD ROUTE ───────────────────────────────────────────────────────
app.post("/api/upload-image", authMiddleware, upload.single("image"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No image uploaded" });
  res.json({
    success: true,
    image_url: `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`,
  });
});

// ─── HEALTH CHECK ─────────────────────────────────────────────────────────────
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", message: "💬 ChatApp API is running!" });
});

// ─── SOCKET.IO ────────────────────────────────────────────────────────────────
const onlineUsers = new Map(); // userId → socketId

io.on("connection", (socket) => {
  console.log(`🔌 Socket connected: ${socket.id}`);

  // User comes online
  socket.on("user_online", async (userId) => {
    onlineUsers.set(userId, socket.id);
    socket.userId = userId;

    // Update DB
    try {
      await User.findByIdAndUpdate(userId, { is_online: true, socket_id: socket.id });
    } catch {}

    // Broadcast to all
    io.emit("user_status", { userId, is_online: true });
    console.log(`✅ User online: ${userId}`);
  });

  // Send message
  socket.on("send_message", async (data) => {
    const { sender_id, receiver_id, text, image_url } = data;

    try {
      // Save to DB
      const msg = await Message.create({
        sender_id, receiver_id,
        text: text || "",
        image_url: image_url || null,
        status: "sent",
      });

      // Send to receiver if online
      const receiverSocketId = onlineUsers.get(receiver_id);
      if (receiverSocketId) {
        io.to(receiverSocketId).emit("receive_message", {
          _id: msg._id,
          sender_id, receiver_id,
          text: text || "",
          image_url: image_url || null,
          timestamp: msg.createdAt,
          status: "delivered",
          reactions: [],
        });

        // Update status to delivered
        await Message.findByIdAndUpdate(msg._id, { status: "delivered" });
        socket.emit("message_delivered", { messageId: msg._id });
      }

      // Confirm sent to sender
      socket.emit("message_sent", {
        _id: msg._id,
        tempId: data._id,
        status: receiverSocketId ? "delivered" : "sent",
      });

    } catch {
      // Demo mode — just forward the message
      const receiverSocketId = onlineUsers.get(receiver_id);
      if (receiverSocketId) {
        io.to(receiverSocketId).emit("receive_message", {
          ...data,
          timestamp: new Date(),
          status: "delivered",
        });
      }
    }
  });

  // Typing indicator
  socket.on("typing", ({ to }) => {
    const receiverSocketId = onlineUsers.get(to);
    if (receiverSocketId) {
      io.to(receiverSocketId).emit("typing", { from: socket.userId });
    }
  });

  // Message read
  socket.on("message_read", async ({ chatUserId }) => {
    try {
      const updated = await Message.updateMany(
        { sender_id: chatUserId, receiver_id: socket.userId, status: { $ne: "read" } },
        { status: "read" }
      );

      // Notify sender
      const senderSocketId = onlineUsers.get(chatUserId);
      if (senderSocketId && updated.modifiedCount > 0) {
        io.to(senderSocketId).emit("messages_read", { by: socket.userId });
      }
    } catch {}
  });

  // Add reaction
  socket.on("add_reaction", async ({ messageId, emoji, receiverId }) => {
    try {
      await Message.findByIdAndUpdate(messageId, {
        $push: { reactions: { emoji, from: socket.userId } },
      });
      const receiverSocketId = onlineUsers.get(receiverId);
      if (receiverSocketId) {
        io.to(receiverSocketId).emit("reaction_added", { messageId, emoji, from: socket.userId });
      }
    } catch {}
  });

  // Disconnect
  socket.on("disconnect", async () => {
    if (socket.userId) {
      onlineUsers.delete(socket.userId);
      try {
        await User.findByIdAndUpdate(socket.userId, {
          is_online: false,
          last_seen: new Date(),
          socket_id: null,
        });
      } catch {}
      io.emit("user_status", { userId: socket.userId, is_online: false });
      console.log(`❌ User offline: ${socket.userId}`);
    }
  });
});

// ─── START SERVER ─────────────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`\n💬 ChatApp Backend running on http://localhost:${PORT}`);
  console.log(`📡 Socket.io ready`);
  console.log(`🗄️  Connecting to MongoDB...`);
});

