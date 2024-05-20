const Hapi = require("@hapi/hapi");
const routes = require("./Routes");
require('dotenv').config();

const init = async () => {
    const server = Hapi.server({
      port: process.env.PORT,
      host: "localhost",
      routes: {
        cors: {
          origin: ["*"],
        },
      },
    });
  
    server.route(routes);
  
    await server.start();
    console.log("Server running on %s", server.info.uri);
  };
  
  process.on("unhandledRejection", (err) => {
    console.error(err);
    process.exit(1);
  });
  
  init();