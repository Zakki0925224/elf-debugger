const path = require("path");
const bodyParser = require("body-parser");
const express = require("express");
const app = express();

let info = {};

app.use(express.static(path.join(__dirname, "web")));
app.use(bodyParser.urlencoded({ extended: true }));

app.post("/api", (req, res) =>
{
    info = req.body;

    console.log(info);

    res.send("OK");
});

app.get("/api", (_, res) =>
{
    res.json(info);
});

app.get("/", (_, res) =>
{
    res.sendFile(path.join(__dirname, "web", "index.html"));
});

let server = app.listen(3000, function ()
{
    console.log("Node.js is listening to PORT:" + server.address().port);
});