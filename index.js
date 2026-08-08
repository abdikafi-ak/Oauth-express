import express from "express";
import googleClient from "./config/google.js";
import { google } from "googleapis";
const app = express();

const port = 5000;

app.get("/api/auth/google", (req, res) => {
    const authUrl = googleClient.generateAuthUrl({
        access_type: "offline",
        scope: [
            "openid",
            "email",
            "profile"
        ],
        prompt: "select_account",
    });
    res.redirect(authUrl);
});

app.get("/api/auth/google/callback", async (req, res) => {
    try {
        const { code } = req.query;

        if (!code) {
            return res.status(400).json({
                success: false,
                message: "Authorization code is missing",
            });
        }

        // Exchange authorization code for tokens
        const { tokens } = await googleClient.getToken(code);

        // Set the tokens on the OAuth client
        googleClient.setCredentials(tokens);

        // Get Google user information
        const oauth2Client = googleClient;

        const { data } = await google.oauth2({
            auth: oauth2Client,
            version: "v2",
        }).userinfo.get();

        console.log("Google User:", data);

        res.json({
            success: true,
            user: data,
        });

    } catch (error) {
        console.error("Google OAuth Error:", error);

        res.status(500).json({
            success: false,
            message: "Google authentication failed",
        });
    }
});


app.listen(port, () => {
    console.log(`Server running on PORT ${port}`);
});