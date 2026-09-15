/** @type {import('next').NextConfig} */
export default {
  // Every outbound call in this app happens on the server, which is the point: ntcept
  // supervises the Next.js process, so it sees the server's egress. A fetch made in the
  // browser would leave from the browser and never reach ntcept.
  reactStrictMode: true,
};
