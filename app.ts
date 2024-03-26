import { handleCpes } from "./cpe";
import { handleCves } from "./cve";

const CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0";

const params = {
  startIndex: 0,
};

const run = async () => {
  // await handleCpes(CPE_API_URL, params);
  await handleCves(CVE_API_URL, params);
};

run();
