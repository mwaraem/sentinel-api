const express = require("express");

const { createScan, getScans, getScanById } = require("../controllers/scan.controller");

const validate = require("../middleware/validate.middleware");
const protect = require("../middleware/auth.middleware");

const { createScanSchema } = require("../validators/scan.validator");

const router = express.Router();

router.post(
    "/",
    protect,
    validate(createScanSchema),
    createScan
);

router.get(
    "/",
    protect,
    getScans
);

router.get(
    "/:id",
    protect,
    getScanById
)

module.exports = router;