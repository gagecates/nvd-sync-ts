import { Db, MongoClient } from "mongodb";
import * as dotenv from "dotenv";

dotenv.config();

const MONGODB_URI: string = process.env.MONGO_URI!;
const DATABASE_NAME: string = process.env.MONGO_DB!;

let dbInstance: Db | null = null;

export const connectToDatabase = async (): Promise<Db> => {
  if (dbInstance) {
    return dbInstance;
  }

  try {
    const client: MongoClient = new MongoClient(MONGODB_URI);
    await client.connect();
    dbInstance = client.db(DATABASE_NAME);
    console.log("Successfully connected to MongoDB.");
    return dbInstance;
  } catch (error) {
    console.error("Failed to connect to MongoDB:", error);
    process.exit(1);
  }
};
