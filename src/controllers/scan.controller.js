const mongoose = require("mongoose");

const Scan = require("../models/scan.model");

const {
    validateTarget,
} = require("../services/target-validation.service");

const {
    scanSecurityHeaders,
} = require("../services/header-scanner.service");

const createScan = async (req, res) => {
    try {
        const { target } = req.body;

        await validateTarget(target);

        const scan = await Scan.create({
            user: req.user,
            target,
            status: "running",
        });

        try {
            const result = await scanSecurityHeaders(target);

            scan.status = "completed";
            scan.findings = result.findings;

            await scan.save();

            return res.status(201).json({
                message: "Scan completed successfully",
                scan: {
                    id: scan._id,
                    target: scan.target,
                    status: scan.status,
                    findings: scan.findings,
                    createdAt: scan.createdAt,
                    updatedAt: scan.updatedAt,
                },
            });
        } catch (scannerError) {
            console.error(
                "Scanner error:",
                scannerError
            );

            scan.status = "failed";

            await scan.save();

            return res.status(502).json({
                message: "Unable to scan target",
                scan: {
                    id: scan._id,
                    target: scan.target,
                    status: scan.status,
                },
            });
        }
    } catch (error) {
        console.error("Create scan error:", error);

        return res.status(400).json({
            message: error.message,
        });
    }
};

const getScans = async (req, res) => {
    try {
        const scans = await Scan.find({
            user: req.user,
        }).sort({ createdAt: -1 });

        return res.status(200).json({
            scans,
        });
    } catch (error) {
        console.error("Get scans error:", error);

        return res.status(500).json({
            message: "Internal server error",
        });
    }
};

const getScanById = async (req, res) => {
    try {
        const { id } = req.params;

        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({
                message: "Invalid scan ID",
            })
        }

        const scan = await Scan.findOne({
            _id: req.params.id,
            user: req.user,
        }).select(
            "_id target status findings createdAt updatedAt"
        );

        if (!scan) {
            return res.status(404).json({
                message: "Scan not found",
            });
        }

        return res.status(200).json({
            scan,
        });
    } catch (error) {
        console.error("Get scan error:", error);

        return res.status(500).json({
            message: "Internal server error",
        });
    }
};

module.exports = {
    createScan,
    getScans,
    getScanById,
};