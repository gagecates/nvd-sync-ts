import axios from "axios";
import { determineCveCpes, determineCvss, determineCwe } from "./utils/util";
import { connectToDatabase } from "./db";

// fetch all parse/store all CPEs from NVD
export const handleCves = async (
  base_url: string,
  params: { startIndex: number },
  delay = 6000,
) => {
  const allCves: any[] = [];
  const db = await connectToDatabase();
  let continueFetching = true;

  // continue to fetch and update pagination params until no records left
  while (continueFetching) {
    try {
      const response = await axios.get(base_url, { params, timeout: 60000 });
      if (response.status === 200) {
        const data = response.data;
        const cves = data.vulnerabilities;

        for (const cve of cves) {
          const obj = cve.cve;
          const {
            id,
            descriptions,
            vulnStatus,
            references,
            configurations,
            weaknesses,
            metrics,
            published,
            lastModified,
          } = obj;
          const descriptionValue = descriptions?.[0]?.value;
          const refUrls = references.map(
            (ref: Record<string, string>) => ref.url,
          );
          // query db for all CPE's respecting versions matching etc.
          const { vulnConfigs, vulnProducts, vendors, products } =
            await determineCveCpes(configurations);
          const cwe = determineCwe(weaknesses);
          const cvss = determineCvss(metrics);
          const details = {
            cveId: id,
            description: descriptionValue,
            nvdStatus: vulnStatus,
            references: refUrls,
            cvss,
            cwe,
            vulnerableConfigs: vulnConfigs,
            vulnerableProducts: vulnProducts,
            vendors,
            products,
            published,
            lastModified,
            timestamp: data.timestamp,
          };

          allCves.push(details);
        }

        const total = data.totalResults;
        const fetchedCount = allCves.length;

        // If to fetch, 6-second delay and continue fetching, otherwise exit
        if (fetchedCount < total) {
          params.startIndex += data.resultsPerPage;
          console.log(`Fetched ${fetchedCount} of ${total} CVES...`);
          // 6-second delay between fetches to respect cap
          await new Promise((resolve) => setTimeout(resolve, delay));
        } else {
          continueFetching = false;
        }
      } else {
        console.log(`Failed to fetch CVEs: ${response.status}`);
      }
    } catch (error) {
      console.error(error);
      return;
    }
  }
  console.log(
    `Successfully fetched ${allCves.length} CVE's. Inserting to DB...`,
  );
  // await db.collection("cves").insertMany(allCves);
};
