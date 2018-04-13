package STGC;


import java.util.concurrent.ConcurrentHashMap;


public class MyCache  {

	private static final int CLEAN_UP_PERIOD_IN_SEC = 5;

	private final ConcurrentHashMap<Integer, Long> cache = new ConcurrentHashMap<>();

	public MyCache() {
		
		Thread cleanerThread = new Thread(() -> {
			while (!Thread.currentThread().isInterrupted()) {
				try {
					Thread.sleep(CLEAN_UP_PERIOD_IN_SEC * 1000);
					for (Integer key: cache.keySet()) {

						if(isExpired(cache.get(key))){
							cache.remove(key);
						}

					}
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
			}
		});

		cleanerThread.setDaemon(true);
		cleanerThread.start();
	}

	public void add( Integer nonce, long periodInMillis) {
		if (nonce == null) {
			return;
		}
		else {
			long expiryTime = System.currentTimeMillis() + periodInMillis;

			cache.put(nonce, expiryTime);
		}
	}

	public void remove(Integer key) {
		cache.remove(key);
	}

	public boolean isValid(Integer nOnce) {

		Long time=cache.get(nOnce);
		if(time == null) return true;
		return isExpired(time);
	}

	public void clear() {
		cache.clear();
	}
	public boolean isExpired(long expiryTime) {
		return System.currentTimeMillis() > expiryTime;
	}



}
