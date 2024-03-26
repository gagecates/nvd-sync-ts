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

interface CweDescription {
  lang: string;
  value: string;
}

type Weakness = {
  description: {
    lang: string;
    value: string;
  }[];
};

export const getVendorProduct = (cpe: string): [string, string] => {
  const parts = cpe.split(":");
  const vendor = parts[3];
  const product = parts[4];
  return [vendor, product];
};

export const getPaddedVersion = (version: string): string => {
  if (version === "-" || version === "") {
    return version;
  }

  version = version.replace("\\(", ".").replace("\\)", ".").replace(/\.$/, "");
  const retList: string[] = [];
  const splittedVersion = version.split(".");

  try {
    parseInt(splittedVersion[splittedVersion.length - 1]);
    // Can be parsed to an integer, proceed normally
    splittedVersion.forEach((v) => {
      try {
        retList.push(parseInt(v).toString().padStart(5, "0"));
      } catch (error) {
        retList.push(v.padStart(5, "0"));
      }
    });
  } catch (error) {
    // Last part of version cannot be cast to an int
    // Handle accordingly...
    // Similar to your Python logic, adapted for TypeScript
  }

  return retList.join(".");
};

type CpeUri = {
  criteria: string;
  versionStartExcluding?: string;
  versionEndExcluding?: string;
  versionStartIncluding?: string;
  versionEndIncluding?: string;
};

export const getVersion = (stem: string): string => {
  const cpeList = stem.split(":");
  const version_stem = cpeList[5];
  return cpeList[6] !== "*" && cpeList[6] !== "-"
    ? `${version_stem}.${cpeList[6]}`
    : version_stem;
};

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

const getCpeFromMongo = async (query: Record<string, any>): Promise<any[]> => {
  const db = await connectToDatabase();
  const result = await db.collection("cpes").find(query).toArray();
  console.log("get cpe from mongo result", result);
  return result;
};

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
