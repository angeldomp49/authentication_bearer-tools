package org.makechtec.bearer_authentication.tools.concordion.support;

public class TimingMeasurement {
    
    private long startTime;
    private long endTime;
    
    public void start() {
        this.startTime = System.nanoTime();
    }
    
    public void end() {
        this.endTime = System.nanoTime();
    }
    
    public long getDurationNanos() {
        return endTime - startTime;
    }
    
    public double getDurationMillis() {
        return (endTime - startTime) / 1_000_000.0;
    }
    
    public static boolean isTimingSafe(long duration1, long duration2, double maxRatio) {
        if (duration1 <= 0 || duration2 <= 0) {
            return false;
        }
        
        double ratio = (double) Math.max(duration1, duration2) / Math.min(duration1, duration2);
        return ratio <= maxRatio;
    }
    
    public static TimingResult measureOperation(Runnable operation) {
        TimingMeasurement measurement = new TimingMeasurement();
        measurement.start();
        
        try {
            operation.run();
            measurement.end();
            return new TimingResult(measurement.getDurationNanos(), null);
        } catch (Exception e) {
            measurement.end();
            return new TimingResult(measurement.getDurationNanos(), e);
        }
    }
    
    public static class TimingResult {
        private final long durationNanos;
        private final Exception exception;
        
        public TimingResult(long durationNanos, Exception exception) {
            this.durationNanos = durationNanos;
            this.exception = exception;
        }
        
        public long getDurationNanos() {
            return durationNanos;
        }
        
        public double getDurationMillis() {
            return durationNanos / 1_000_000.0;
        }
        
        public boolean hasException() {
            return exception != null;
        }
        
        public Exception getException() {
            return exception;
        }
        
        public boolean isSuccess() {
            return exception == null;
        }
    }
    
    public static double calculateTimingRatio(long time1, long time2) {
        if (time1 <= 0 || time2 <= 0) {
            return Double.MAX_VALUE;
        }
        return (double) Math.max(time1, time2) / Math.min(time1, time2);
    }
    
    public static String formatDuration(long nanos) {
        if (nanos < 1_000) {
            return nanos + " ns";
        } else if (nanos < 1_000_000) {
            return String.format("%.2f μs", nanos / 1_000.0);
        } else if (nanos < 1_000_000_000) {
            return String.format("%.2f ms", nanos / 1_000_000.0);
        } else {
            return String.format("%.2f s", nanos / 1_000_000_000.0);
        }
    }
}
