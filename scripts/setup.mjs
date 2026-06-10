#!/usr/bin/env node
import { bootstrapReceiptKeys } from "./bootstrap_dev_receipt_keys.mjs";
import "./tester-id.mjs";

const keyResult = bootstrapReceiptKeys();
console.log(keyResult.message);
