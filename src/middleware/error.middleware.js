const errorHandler = (err, req, res, next) => {
    console.error(err.stack);

    if (err.name === "ValidationError") {
        return res.status(400).json({
            message: "Validation failed",
        });
    }

    if (err.name === "CastError") {
        return res.status(400).json({
            message: "Invalide resource ID",
        })
    }

    return res.status(err.statusCode || 500).json({
        message: 
            process.env.NODE_ENV === "production"
            ? "Internal server errror"
            : err.message || "Internal server errror",
    });
};

module.exports = errorHandler;