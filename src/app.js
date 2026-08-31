const express = require("express");

const healthRoutes = require("./routes/health.routes");
const authRoutes = require("./routes/auth.routes");
const scanRoutes = require("./routes/scan.routes");

const errorHandler = require("./middleware/error.middleware");

const app = express();

app.use(express.json());

app.use("/api/v1/health", healthRoutes);
app.use("/api/v1/auth", authRoutes);
app.use("/api/v1/scans", scanRoutes);

app.use(errorHandler);

module.exports = app;