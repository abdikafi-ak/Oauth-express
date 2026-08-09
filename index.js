import express from "express";
import googleClient from "./config/google.js";
import crypto from "crypto"
import { google } from "googleapis";
import cookieParser from "cookie-parser";
import axios from "axios";
const app = express();

const port = 5000;

app.use(cookieParser())
app.use(express.json())

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

app.get("/api/auth/github", (req, res) => {

    const state = crypto.randomBytes(32).toString("hex");

    res.cookie("github_oauth_state", state, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 10 * 60 * 1000
    });

    const params = new URLSearchParams({
        client_id: process.env.GITHUB_CLIENT_ID,

        redirect_uri:
            process.env.GITHUB_CALLBACK_URL,

        scope: "user:email",

        state,

        allow_signup: "true"
    });

    const githubUrl =
        `https://github.com/login/oauth/authorize?${params.toString()}`;

    res.redirect(githubUrl);
});

app.get("/api/auth/github/callback", async (req, res) => {
    try {
        const { code, state, error, error_description } = req.query;
        const savedState =
            req.cookies.github_oauth_state;

        res.clearCookie("github_oauth_state");


        console.log(error_description)

        if (!code) {
            return res.status(400).json({
                success: false,
                message:
                    "GitHub authorization code is missing"
            });
        }

        if (!state || state !== savedState) {
            return res.status(400).json({
                success: false,
                message:
                    "Invalid OAuth state"
            });
        }

        const tokenResponse =
            await axios.post(
                "https://github.com/login/oauth/access_token",
                {
                    client_id:
                        process.env.GITHUB_CLIENT_ID,

                    client_secret:
                        process.env.GITHUB_CLIENT_SECRET,

                    code,

                    redirect_uri:
                        process.env.GITHUB_CALLBACK_URL
                },
                {
                    headers: {
                        Accept:
                            "application/json"
                    }
                }
            );

        const githubAccessToken =
            tokenResponse.data.access_token;

        if (!githubAccessToken) {
            throw new Error(
                "GitHub access token was not returned"
            );
        }

        const userResponse =
            await axios.get(
                "https://api.github.com/user",
                {
                    headers: {
                        Authorization:
                            `Bearer ${githubAccessToken}`,

                        Accept:
                            "application/vnd.github+json",

                        "X-GitHub-Api-Version":
                            "2026-03-10"
                    }
                }
            );

        const githubUser =
            userResponse.data;
        console.log(githubUser)

        const emailResponse =
            await axios.get(
                "https://api.github.com/user/emails",
                {
                    headers: {
                        Authorization:
                            `Bearer ${githubAccessToken}`,

                        Accept:
                            "application/vnd.github+json",

                        "X-GitHub-Api-Version":
                            "2026-03-10"
                    }
                }
            );

        const primaryEmail =
            emailResponse.data.find(
                email =>
                    email.primary &&
                    email.verified
            );

        if (!primaryEmail) {
            return res.status(400).json({
                success: false,
                message:
                    "No verified primary email was found"
            });
        }

        return res.json({
            success: true,
            message: "GitHub login successful"
        });

    } catch (error) {

        console.error(
            "GitHub OAuth Error:",
            error.response?.data || error
        );

        return res.status(500).json({
            success: false,
            message:
                "GitHub authentication failed"
        });
    }
});

app.listen(port, () => {
    console.log(`Server running on PORT ${port}`);
});