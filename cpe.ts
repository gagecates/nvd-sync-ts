import axios from "axios";
import { getPaddedVersion, getVersion } from "./utils/util";
import { connectToDatabase } from "./db";

// fetch all parse/store all CPEs from NVD
export const handleCpes = async (
  base_url: string,
  params: { startIndex: number },
  delay = 6000,
) => {
  const allCpes: any[] = [];
  const db = await connectToDatabase();
  let continueFetching = true;

  // continue to fetch and update pagination params until no records left
  while (continueFetching) {
    try {
      const response = await axios.get(base_url, { params, timeout: 60000 });
      if (response.status === 200) {
        const data = response.data;
        const cpes = data.products;

        for (const cpe of cpes) {
          const obj = cpe.cpe;
          const cpeName = obj.cpeName;
          const items = cpeName.split(":");
          const vendor = items[3];
          const product = items[4];
          const version = getVersion(cpeName);
          const details = {
            cpe: cpeName,
            cpeNameId: obj.cpeNameId,
            vendor: vendor,
            product: product,
            version: version,
            paddedVersion: getPaddedVersion(version),
            deprecated: obj.deprecated,
            deprecatedBy: obj.deprecatedBy || "",
            created: obj.created,
            lastModified: obj.lastModified,
            timestamp: data.timestamp,
          };

          allCpes.push(details);
        }

        const total = data.totalResults;
        const fetchedCount = allCpes.length;

        // If to fetch, 6-second delay and continue fetching, otherwise exit
        if (fetchedCount < total) {
          params.startIndex += data.resultsPerPage;
          console.log(`Fetched ${fetchedCount} of ${total} CPES...`);
          // 6-second delay between fetches to respect cap
          await new Promise((resolve) => setTimeout(resolve, delay));
        } else {
          continueFetching = false;
        }
      } else {
        console.log(`Failed to fetch CPEs: ${response.status}`);
      }
    } catch (error) {
      console.error(error);
      return;
    }
  }
  console.log(`Successfully fetched ${allCpes.length}. Inserting to DB...`);
  // await db.collection("cpes").insertMany(allCpes);
};
