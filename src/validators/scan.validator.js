const { z } = require("zod");

const createScanSchema = z.object({
    target: z
        .string()
        .trim()
        .url("Target must be a valid URL")
        .max(2048, "Target URL is too long"),
});

module.exports = {
    createScanSchema,
};