import os
import logging
import json
from datetime import datetime, timedelta
import redis
from apscheduler.schedulers.blocking import BlockingScheduler

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

# Connect to Redis
redis_host = os.getenv('REDIS_HOST', 'redis')
redis_port = int(os.getenv('REDIS_PORT', 6379))
redis_db = int(os.getenv('REDIS_DB', 0))
r = redis.StrictRedis(host=redis_host, port=redis_port, db=redis_db)

logger.info(" ____    ____   ")
logger.info("|  _ \  |  _ \  ╔═════════════════════════╗")
logger.info("| | | | | |_) | ║   eworx                 ║")
logger.info("| |_| | |  _ <  ║   ip webhook -- cron    ║")
logger.info("|____/  |_| \_\ ╚═════════════════════════╝")
logger.info("starting.....")

def clean_old_ips():
    """Function to clean IPs older than 24 hours from Redis."""
    threshold_time_utc = datetime.utcnow() - timedelta(hours=24)
    ips_with_dates = r.hgetall('ips')
    
    for ip, data_str in ips_with_dates.items():
        ip = ip.decode('utf-8')
        try:
            data = json.loads(data_str.decode('utf-8'))
            timestamp_str = data['timestamp'].replace(' UTC', '')
            date_added = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            
            if date_added < threshold_time_utc:
                r.hdel('ips', ip)
                logger.info(f"Deleted IP {ip} added on {timestamp_str} as it is older than 24 hours.")
        except Exception as e:
            logger.error(f"Error processing data for IP {ip}: {e}. Skipping...")

def clean_old_ips_webhook2_whitelist():
    """Function to clean IPs older than 24 hours from Redis in ips_webhook2_whitelist."""
    threshold_time_utc = datetime.utcnow() - timedelta(hours=24)
    ips_with_dates = r.hgetall('ips_webhook2_whitelist')
    
    for ip, data_str in ips_with_dates.items():
        ip = ip.decode('utf-8')
        try:
            data = json.loads(data_str.decode('utf-8'))
            timestamp_str = data['timestamp'].replace(' UTC', '')
            date_added = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            
            if date_added < threshold_time_utc:
                r.hdel('ips_webhook2_whitelist', ip)
                logger.info(f"Deleted IP {ip} from whitelist added on {timestamp_str} as it is older than 24 hours.")
        except Exception as e:
            logger.error(f"Error processing data for IP {ip} in whitelist: {e}. Skipping...")

# Create a scheduler instance
scheduler = BlockingScheduler()

# Schedule the clean_old_ips function to run every 15 minutes
scheduler.add_job(clean_old_ips, 'interval', minutes=15)

# Schedule the clean_old_ips_webhook2_whitelist function to run every 15 minutes
scheduler.add_job(clean_old_ips_webhook2_whitelist, 'interval', minutes=15)

if __name__ == '__main__':
    logger.info("Starting scheduler to clean old IPs and whitelist.")
    scheduler.start()
