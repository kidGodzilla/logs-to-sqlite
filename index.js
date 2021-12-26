require('dotenv').config();

const { Parser } = require('@robojones/nginx-log-parser');
const geoipCountry = require('geoip-country');
const MobileDetect = require('mobile-detect');
const syncViaFtp = require('sync-via-ftp');
const Database = require('better-sqlite3');
const lineByLine = require('n-readlines');
const anonymize = require('ip-anonymize');
const schedule = require('node-schedule');
const uaparser = require('ua-parser');
const request = require('superagent');
const express = require('express');
const Url = require('url-parse');
const crypto = require('crypto');
const fs = require('fs');

let debug = process.env.DEBUG || false;
const PORT = process.env.PORT || 5001;
const app = express();
let hwms = {};
let drop = 1;
let db;


const schema = '$remote_addr - $remote_user [$time_local] "$request" $status $bytes_sent "$http_referer" "$http_user_agent"'
const nginxParser = new Parser(schema);

// Determine device type
function determineDeviceType(ua, type) {
    let deviceType = 'mobile,tablet,desktop,laptop'.split(',');
    let md = new MobileDetect(ua);

    // md.maxPhoneWidth 992 - 1440 = laptop
    // console.log(md.maxPhoneWidth)

    if (!(md.mobile() || md.tablet())) type = 2;
    else if (!!md.mobile()) type = 0;
    else if (!!md.tablet()) type = 1;

    // Attempted but Not very accurate
    // if (type === 2 && md.maxPhoneWidth <= 1440) type = 3;

    // console.log('\n', deviceType[type], '\n');
    return deviceType[type];
}

async function constructDb() {
    // Use SQLite3 Database
    db = new Database('nginx.sqlite3'); // , { verbose: console.log }

    // Drop previous `visits` table
    if (drop) {
        let stmt = db.prepare(`DROP TABLE IF EXISTS visits`);
        console.log('Dropping previous visits table');
        await stmt.run();
    }

    // Optional Recommended Improvements
    stmt = db.prepare(`pragma journal_mode = delete;`);
    await stmt.run();

    stmt = db.prepare(`pragma page_size = 1024;`);
    await stmt.run();

    stmt = db.prepare(`vacuum;`);
    await stmt.run();

    // Create `visits` Table // id TEXT PRIMARY KEY
    stmt = db.prepare(`CREATE TABLE IF NOT EXISTS visits (
        id INTEGER PRIMARY KEY,
        date TEXT,
        ts INTEGER,
        day TEXT,
        hour TEXT,
        ip TEXT,
        url TEXT,
        protocol TEXT,
        pathname TEXT,
        host TEXT,
        device_type TEXT,
        device_family TEXT,
        browser TEXT,
        browser_major_version TEXT,
        browser_minor_version TEXT,
        os TEXT,
        os_major_version TEXT,
        os_minor_version TEXT,
        country_code TEXT,
        referer_host TEXT
    )`);

    await stmt.run();

    // Vacuum again
    stmt = db.prepare(`vacuum;`);
    await stmt.run();
}

function createPreparedStatements() {
    // Insert via prepared statement // INSERT OR IGNORE
    const insert = db.prepare(`INSERT INTO visits (
        date, 
        ts, 
        day, 
        hour,
        ip, 
        url,
        protocol, 
        pathname, 
        host, 
        device_type, 
        device_family, 
        browser, 
        browser_major_version, 
        browser_minor_version, 
        os, 
        os_major_version, 
        os_minor_version, 
        country_code,
        referer_host
    ) VALUES (
        @iso_date,
        @timestamp,
        @day, 
        @hour,
        @remote_addr,
        @url,
        @protocol, 
        @pathname, 
        @host, 
        @device_type, 
        @device_family, 
        @browser, 
        @browser_major_version, 
        @browser_minor_version, 
        @os, 
        @os_major_version, 
        @os_minor_version, 
        @country_code,
        @referer_host
    )`);

    // Insert one or many function
    const insertMany = db.transaction(rows => {
        if (Array.isArray(rows)) {
            for (const row of rows) insert.run(row);
        } else if (typeof rows === 'object') {
            insert.run(rows);
        } else {
            throw new Error('Invalid type for insertMany');
        }
    });

    return { insert, insertMany };
}

function parseRequest(s) {
    let p = s.split(' ');
    return { method: p[0], url: p[1], http_protocol: p[2] };
}

function parseDate(s) {
    return new Date(s.replace(':',' '));
}

function b64(s) {
    return '';
    // return crypto.createHash('sha1').update(s).digest('base64');
}

let ipCountryLookup = {};

function ip2country(ip) {
    // ip = anonymize(ip);
    if (ipCountryLookup[ip]) return ipCountryLookup[ip];
    let country_code = geoipCountry.lookup(ip).country;
    ipCountryLookup[ip] = country_code;
    return country_code;
}

async function init() {
    await constructDb();
    const { insertMany } = createPreparedStatements();
    const liner = new lineByLine('./app-access.log');

    let line, max_iterations = 139044, rows = [], max_rows_per_batch = 50000;
    let high_water_mark = 0, new_high_water_mark = 0;
    let startTime = + new Date(), linesProcessed = 0;
    if (high_water_mark) high_water_mark--;

    try {
        while ((line = liner.next())) { // max_iterations-- &&
            if (line) line = line.toString('utf8');
            if (!line || typeof line !== 'string' || line.length < 9) continue;

            let result = nginxParser.parseLine(line);

            result.timestamp = + parseDate(result.time_local);
            result.iso_date = parseDate(result.time_local).toISOString();

            if (result.timestamp < high_water_mark) continue;
            if (result.timestamp > new_high_water_mark) new_high_water_mark = result.timestamp;

            result.hour = result.iso_date.substr(0, 14)+'00:00.000Z';
            result.day = result.iso_date.substr(0, 10);

            result.parsed_http_referer = new Url(result.http_referer, true);
            result = Object.assign(result, parseRequest(result.request));
            result.parsed_ua = uaparser.parse(result.http_user_agent);
            result.parsed_url = new Url(result.url, true);
            result.country_code = ip2country(result.remote_addr);
            // result.unique_request_id = b64(line);

            result.protocol = result.parsed_url.protocol;
            result.pathname = result.parsed_url.pathname;
            result.host = result.parsed_url.host;
            result.device_type = determineDeviceType(result.http_user_agent);
            result.device_family = result.parsed_ua.device.family;
            result.browser = result.parsed_ua.family;
            result.browser_major_version = result.parsed_ua.major;
            result.browser_minor_version = result.parsed_ua.minor;
            result.os = result.parsed_ua.os.family;
            result.os_major_version = result.parsed_ua.os.major;
            result.os_minor_version = result.parsed_ua.os.minor;
            result.referer_host = result.parsed_http_referer.hostname;

            delete result.bytes_sent;

            // console.log(result);
            rows.push(result);
            linesProcessed++;

            if (rows.length > max_rows_per_batch) {
                insertMany(rows);
                rows = [];
                // Todo: update high_water_mark after insertMany completes
            }
        }

    } catch(e) {
        console.log(e);
    }

    insertMany(rows);

    console.log('Time:', (+ new Date() - startTime) / 1000, 's');
    console.log('New high_water_mark:', new_high_water_mark);
    console.log(linesProcessed, 'lines processed');
}

init();
