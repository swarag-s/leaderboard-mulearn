# app.py
from flask import Flask, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
import os
import asyncio
from playwright.async_api import async_playwright

load_dotenv()

app = Flask(__name__)
CORS(app)

cached_data = None
last_fetch = None
CACHE_DURATION = timedelta(minutes=5)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated

async def scrape_leaderboard_async():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(os.getenv("LOGIN_URL"))

        # Fill login form
        await page.fill('input[name="username"]', os.getenv("USERNAME"))
        await page.fill('input[name="password"]', os.getenv("PASSWORD"))
        await page.press('input[name="password"]', "Enter")

        # Wait for dashboard redirect
        await page.wait_for_url("**/dashboard/**", timeout=10000)

        # Go to leaderboard
        await page.goto(os.getenv("LEADERBOARD_URL"))
        await page.wait_for_selector("table")

        rows = await page.query_selector_all("table tr")
        leaderboard = []

        for i, row in enumerate(rows[1:]):  # skip header
            cols = await row.query_selector_all("td")
            if len(cols) >= 3:
                rank = await cols[0].inner_text()
                name = await cols[1].inner_text()
                points = (await cols[2].inner_text()).replace(",", "").strip()
                leaderboard.append({
                    "rank": int(rank),
                    "name": name.strip(),
                    "points": int(points)
                })

        await browser.close()
        return leaderboard

def scrape_leaderboard():
    return asyncio.run(scrape_leaderboard_async())

# Routes
@app.route("/health")
def health_check():
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})

@app.route("/api/leaderboard", methods=["GET"])
@require_auth
def get_leaderboard():
    global cached_data, last_fetch
    now = datetime.now()
    if cached_data and last_fetch and (now - last_fetch < CACHE_DURATION):
        return jsonify({
            "data": cached_data,
            "cached": True,
            "lastUpdate": last_fetch.isoformat(),
            "count": len(cached_data)
        })
    data = scrape_leaderboard()
    cached_data = data
    last_fetch = now
    return jsonify({
        "data": data,
        "cached": False,
        "lastUpdate": last_fetch.isoformat(),
        "count": len(data)
    })

@app.route("/api/leaderboard/refresh", methods=["POST"])
@require_auth
def refresh_leaderboard():
    global cached_data, last_fetch
    data = scrape_leaderboard()
    cached_data = data
    last_fetch = datetime.now()
    return jsonify({
        "message": "Cache refreshed",
        "data": data,
        "lastUpdate": last_fetch.isoformat(),
        "count": len(data)
    })

@app.route("/api/leaderboard/top/<int:n>", methods=["GET"])
@require_auth
def get_top_n(n):
    global cached_data, last_fetch
    now = datetime.now()
    if not cached_data or not last_fetch or (now - last_fetch >= CACHE_DURATION):
        cached_data = scrape_leaderboard()
        last_fetch = now
    top_players = cached_data[:n] if cached_data else []
    return jsonify({
        "data": top_players,
        "cached": True,
        "lastUpdate": last_fetch.isoformat() if last_fetch else None,
        "count": len(top_players)
    })

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("DEBUG", "True").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
