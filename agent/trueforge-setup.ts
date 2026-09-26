import { ensureIamenderAgent } from "./trueforge.js";

ensureIamenderAgent()
  .then((agent) => console.log(JSON.stringify(agent, null, 2)))
  .catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
