import { connectToDatabase } from "../db";

type Cpes = {
  vendors: string[];
  products: string[];
  vulnConfigs: string[];
  vulnProducts: string[];
};

type Metrics = Record<string, any>;

type CvssData = {
  version: string;
  baseScore: number;
  severity: string;
};

type CweDescription = {
  lang: string;
  value: string;
};

type Weakness = {
  description: {
    lang: string;
    value: string;
  }[];
};

type CpeUri = {
  criteria: string;
  versionStartExcluding?: string;
  versionEndExcluding?: string;
  versionStartIncluding?: string;
  versionEndIncluding?: string;
};

// get vendor and product name from full cpe string e.g. cpe:2.3:a:analogx:proxy:4.13:*:*:*:*:*:*:*
export const getVendorProduct = (cpe: string): [string, string] => {
  const parts = cpe.split(":");
  const vendor = parts[3];
  const product = parts[4];
  return [vendor, product];
};

// get padded version of original version string to help with query lookups e.g. 2.0.2 = 00002.00000.00002
// referenced: https://github.com/cve-search/CveXplore/blob/6f052361318f90bf518d8552f1177a41cca285cb/CveXplore/core/database_maintenance/api_handlers.py#L43
// testing results: (2.5.1-k9 > 00002.00005.00001) (3.0.sp2a > 00003.00000.sp2a) (2.5 > 00002.00005)
export const getPaddedVersion = (version: string): string => {
  if (version === "-" || version === "") {
    return version;
  }

  // Normalizing edge cases
  version = version
    .replace(/\\\(/g, ".")
    .replace(/\\\)/g, ".")
    .replace(/\.$/, "");

  let retList: string[] = [];
  const splittedVersion = version.split(".");

  // Attempt to parse the last part of the version to check if it can be treated as an integer
  if (!isNaN(parseInt(splittedVersion[splittedVersion.length - 1]))) {
    // Can be cast to an int, proceed 'normally'
    splittedVersion.forEach((v) => {
      const parsed = parseInt(v, 10);
      if (!isNaN(parsed)) {
        retList.push(parsed.toString().padStart(5, "0"));
      } else {
        retList.push(v.padStart(5, "0"));
      }
    });
  } else {
    // Last part of the version cannot be cast to an int
    // Handle leading up to the last part
    if (splittedVersion.length > 1) {
      for (let i = 0; i < splittedVersion.length - 1; i++) {
        const parsed = parseInt(splittedVersion[i], 10);
        if (!isNaN(parsed)) {
          retList.push(parsed.toString().padStart(5, "0"));
        } else {
          retList.push(splittedVersion[i].padStart(5, "0"));
        }
      }
    }

    // Handle the last part separately
    const lastPart = splittedVersion[splittedVersion.length - 1];
    if (lastPart.length <= 5) {
      retList.push(lastPart.padStart(5, "0"));
    } else if (/^\d+$/.test(lastPart)) {
      // If it's all digits
      retList.push(parseInt(lastPart, 10).toString().padStart(5, "0"));
    } else {
      // Mix of characters and digits or just characters
      let part = "";
      lastPart.split("").forEach((char) => {
        if (/\d/.test(char)) {
          part += char.padStart(5, "0");
        } else {
          part += char;
        }
      });
      retList.push(part.padStart(5, "0"));
    }
  }

  return retList.join(".");
};

// get version number from full cpe string e.g. cpe:2.3:a:analogx:proxy:4.13:*:*:*:*:*:*:* = 4.13
export const getVersion = (stem: string): string => {
  const cpeList = stem.split(":");
  const version_stem = cpeList[5];
  return cpeList[6] !== "*" && cpeList[6] !== "-"
    ? `${version_stem}.${cpeList[6]}`
    : version_stem;
};

// Takes in the CPE match version start/ends to create a query to find matching CPE's according to cpe and versioning
const createCpeQuery = (cpeUri: CpeUri): Record<string, any> => {
  let query: Record<string, any> = {};

  if (cpeUri.versionStartExcluding) {
    if (cpeUri.versionEndExcluding) {
      query = {
        deprecated: false,
        cpe: cpeUri.criteria,
        paddedVersion: {
          $gt: getPaddedVersion(cpeUri.versionStartExcluding),
          $lt: getPaddedVersion(cpeUri.versionEndExcluding),
        },
      };
    } else if (cpeUri.versionEndIncluding) {
      query = {
        deprecated: false,
        cpe: cpeUri.criteria,
        paddedVersion: {
          $gt: getPaddedVersion(cpeUri.versionStartExcluding),
          $lte: getPaddedVersion(cpeUri.versionEndIncluding),
        },
      };
    } else {
      query = {
        deprecated: false,
        cpe: cpeUri.criteria,
        paddedVersion: {
          $gt: getPaddedVersion(cpeUri.versionStartExcluding),
        },
      };
    }
  } else if (cpeUri.versionStartIncluding) {
    if (cpeUri.versionEndExcluding) {
      query = {
        deprecated: false,
        cpe: cpeUri.criteria,
        paddedVersion: {
          $gte: getPaddedVersion(cpeUri.versionStartIncluding),
          $lt: getPaddedVersion(cpeUri.versionEndExcluding),
        },
      };
    } else if (cpeUri.versionEndIncluding) {
      query = {
        deprecated: false,
        cpe: cpeUri.criteria,
        paddedVersion: {
          $gte: getPaddedVersion(cpeUri.versionStartIncluding),
          $lte: getPaddedVersion(cpeUri.versionEndIncluding),
        },
      };
    } else {
      query = {
        deprecated: false,
        cpe: cpeUri.criteria,
        paddedVersion: {
          $gte: getPaddedVersion(cpeUri.versionStartIncluding),
        },
      };
    }
  } else if (cpeUri.versionEndExcluding) {
    query = {
      deprecated: false,
      cpe: cpeUri.criteria,
      paddedVersion: {
        $lt: getPaddedVersion(cpeUri.versionEndExcluding),
      },
    };
  } else if (cpeUri.versionEndIncluding) {
    query = {
      deprecated: false,
      cpe: cpeUri.criteria,
      paddedVersion: {
        $lte: getPaddedVersion(cpeUri.versionEndIncluding),
      },
    };
  }

  return query;
};

// DB lookup for CPE's
const getCpeFromMongo = async (query: Record<string, any>): Promise<any[]> => {
  const db = await connectToDatabase();
  const startTime = Date.now();
  const result = await db.collection("cpes").find(query).toArray();
  const endTime = Date.now();
  // console.log(`CPE query excution time: ${endTime - startTime} ms`);
  return result;
};

// This extracts the matched CPE's for a specific CVE.
// configurations object contains nodes with AND/OR logic to determine which products by themselves or with others
// are vulnerable. This function extracts the CPE's no matter the logic, and then if a version start/end is provided,
// does a db lookup for CPE's with that cpe string and version (padded).
export const determineCveCpes = async (configs: any = []): Promise<Cpes> => {
  let vendors: string[] = [];
  let products: string[] = [];
  let vulnProducts: string[] = [];
  let vulnConfigs: string[] = [];

  for (const node of configs) {
    for (const cpe of node.nodes) {
      if (cpe.cpeMatch) {
        for (const cpeUri of cpe.cpeMatch) {
          if (!cpeUri.criteria) continue;
          // if not vulnerable, only add to configs
          if (!cpeUri.vulnerable) {
            if (!vulnConfigs.includes(cpeUri.criteria))
              vulnConfigs.push(cpeUri.criteria);
            continue;
          }
          // otherwise, create query for matching cpes according to versioning
          const query = createCpeQuery(cpeUri);
          if (Object.keys(query).length > 0) {
            const cpeInfoList: any = await getCpeFromMongo(query);
            cpeInfoList.sort((a: any, b: any) =>
              a.paddedVersion.localeCompare(b.paddedVersion),
            );
            for (const vulnerableVersion of cpeInfoList) {
              const { cpe, vendor, product } = vulnerableVersion;
              if (!vulnProducts.includes(cpe)) vulnProducts.push(cpe);
              if (!vulnConfigs.includes(cpe)) vulnConfigs.push(cpe);
              if (!vendors.includes(vendor)) vendors.push(vendor);
              if (!products.includes(product)) products.push(product);
            }
          } else {
            // If the cpeMatch did not have version start/end, add the cpe string as is to each array
            const [vendor, product] = getVendorProduct(cpeUri.criteria);
            if (!vulnProducts.includes(cpeUri.criteria))
              vulnProducts.push(cpeUri.criteria);
            if (!vulnConfigs.includes(cpeUri.criteria))
              vulnConfigs.push(cpeUri.criteria);
            if (!vendors.includes(vendor)) vendors.push(vendor);
            if (!products.includes(product)) products.push(product);
          }
        }
      }
    }
  }
  return { vulnProducts, vulnConfigs, vendors, products };
};

// get cvss version, base score, and severity from metrics objects
export const determineCvss = (metrics: Metrics = {}): CvssData[] => {
  const cvss: CvssData[] = [];

  Object.entries(metrics).forEach(([version, metricList]) => {
    metricList.forEach((metric: any) => {
      const cvssData = metric.cvssData;
      const details: CvssData = {
        version: cvssData.version,
        baseScore: cvssData.baseScore,
        // Assuming baseSeverity might not exist on cvssData, fallback to metric's baseSeverity
        severity: metric.baseSeverity ?? cvssData.baseSeverity,
      };

      cvss.push(details);
    });
  });

  return cvss;
};

// find the cwe id from weaknesses object e.g. CWE-843
export const determineCwe = (weaknesses: Weakness[] = []): string => {
  let value = "Unknown"; // Providing default

  weaknesses.forEach((weakness) => {
    weakness.description.forEach((cwe) => {
      if (cwe.lang === "en") {
        value = cwe.value;
      }
    });
  });

  return value;
};
