const { z } = require("zod");

const registerSchema = z.object({
    name: z
        .string()
        .trim()
        .min(2, "Name must be at least 2 characters long")
        .max(50, "Name must not exceed 50 characters"),
    email: z
        .string()
        .trim()
        .email("Please provide email address"),

    password: z
        .string()
        .min(8, "Password must be at least 8 characters long")
        .max(100, "Password must not exceed 100 characters"),
});

module.exports = {
    registerSchema,
};