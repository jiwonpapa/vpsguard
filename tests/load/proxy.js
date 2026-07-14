import http from "k6/http";
import { check } from "k6";

export const options = {
  vus: Number(__ENV.VUS || 10),
  duration: __ENV.DURATION || "30s",
  thresholds: {
    http_req_failed: ["rate==0"],
    http_req_duration: ["p(95)<250"],
  },
};

export default function () {
  const response = http.get(__ENV.TARGET_URL || "http://127.0.0.1:18080/hello", {
    headers: { Host: __ENV.TARGET_HOST || "example.test" },
  });
  check(response, { "proxy returned success": (value) => value.status === 200 });
}
