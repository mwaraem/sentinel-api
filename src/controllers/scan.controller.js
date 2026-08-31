const Scan = require("../models/scan.model");

const createScan = async (req, res) => {
    try {
        const { target } = req.body;

        const scan = await Scan.create({
            user: req.user,
            target,
        });

        return res.status(201).json({
            message: "Scan created successfully",
            scan: {
                id: scan._id,
                target: scan.target,
                status: scan.status,
                createdAt: scan.createdAt,
            },
        });
    } catch (error) {
        console.error("Create scan error:", error);

        return res.status(500).json({
            message: "Internal server error",
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