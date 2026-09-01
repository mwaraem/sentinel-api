const mongoose = require("mongoose");

const scanSchema = new mongoose.Schema(
    {
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
        },

        target: {
            type: String,
            required: true,
            trim: true,
        },

        status: {
            type: String,
            enum: ["pending", "running", "completed", "failed"],
            default: "pending",
        },

        score: {
            type: Number,
            min: 0,
            max: 100,
        },

        findings: [
            {
                type: {
                    type: String,
                    required: true,
                },

                severity: {
                    type: String,
                    enum: ["critical",
                    "high",
                    "medium",
                    "low",
                    "info",],
                    required: true,
                },

                title: {
                    type: String,
                    required: true,
                },

                description: {
                    type: String,
                    required: true,
                },

                recommendation: {
                    type: String,
                    required: true,
                },
            },
        ],
    },
    {
        timestamps: true,
    }
);

const Scan = mongoose.model("Scan", scanSchema);

module.exports = Scan;