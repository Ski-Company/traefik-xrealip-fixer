import http from "k6/http";
import { check, sleep } from "k6";

// Basic, fast benchmark against whoami through Traefik.
// Override via env: TARGET_URL, VUS, DURATION.
export const options = {
  vus: Number(__ENV.VUS || 10),
  duration: __ENV.DURATION || "20s",
};

const url = __ENV.TARGET_URL || "http://traefik/";
const hostHeader = __ENV.HOST || "whoami.local";
const xffHeader = __ENV.XFF || "203.0.113.10, 10.0.0.1";

export default function () {
  const res = http.get(url, {
    headers: {
      Host: hostHeader,
      "X-Forwarded-For": xffHeader,
    },
  });
  check(res, {
    "status is 200": (r) => r.status === 200,
    "body non-empty": (r) => r.body && r.body.length > 0,
  });
  // Small think time to avoid unrealistic hammering
  sleep(0.1);
}
