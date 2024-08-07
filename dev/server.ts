import { Elysia } from 'elysia';
import {initDID} from "./index";

console.log('start create server');
const app = new Elysia()
  .get('/create', () => initDID())
  .listen(8001)

console.log(`🔍 DID creator is running at on port ${app.server?.port}...`)
