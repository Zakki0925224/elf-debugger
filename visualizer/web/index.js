const ws = new WebSocket("ws://localhost:3030");
ws.onopen = () => console.log("Connected to the server");

ws.onmessage = event => console.log(JSON.parse(event.data));

ws.onclose = () => console.log("Disconnected from the server");
