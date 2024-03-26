import { handleCpes } from "./cpe";
import { handleCves } from "./cve";
import semver from "semver";
import { getPaddedVersion } from "./utils/util";

const CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0";

const params = {
  startIndex: 0,
};

const run = async () => {
  // await handleCpes(CPE_API_URL, params);
  //await handleCves(CVE_API_URL, params);
};

run();

// TODO:
// Determine what to do with config object in CVE, store or ignore
// Run and populate CVES
// Clean/remove comments
// Add to FE app
