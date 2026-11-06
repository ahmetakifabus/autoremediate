// Demo hedefi: kasıtlı olarak zafiyetli Express uygulaması. ÇALIŞTIRMAYIN.
const express = require('express');
const { exec, execFile } = require('child_process');
const fs = require('fs');
const _ = require('lodash');
const serialize = require('node-serialize');

const app = express();
const config = {};

app.get('/ping', (req, res) => {
  const { host } = req.query;
  exec(`ping -c 1 ${host}`, (err, out) => res.send(out));
});

app.post('/settings', (req, res) => {
  _.merge(config, req.body);
  res.sendStatus(204);
});

app.get('/file', (req, res) => {
  res.sendFile(req.query.path);
});

app.get('/user', async (req, res) => {
  const rows = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
  res.json(rows);
});

app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  const r = await fetch(target);
  res.send(await r.text());
});

app.get('/hello', (req, res) => {
  res.send(`<h1>Merhaba ${req.query.name}</h1>`);
});

// Güvenli kullanımlar (bulgu üretmemeli):
app.get('/ls', (req, res) => {
  const dir = req.query.dir;
  execFile('ls', [dir], (e, out) => res.send(out));
});

const agent = new https.Agent({ rejectUnauthorized: false });
