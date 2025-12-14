using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace DataProducer;

public class Worker(ILogger<Worker> logger) : BackgroundService
{
    private readonly static ActivitySource s_activitySource = new("DataProducer.Worker");
    
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        int execution = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            ++execution;
            using Activity? activity = s_activitySource.StartActivity("WorkerExecution");
            activity?.SetTag("Execution", execution);
            logger.LogInformation("Worker running at: {ExecutionTime}", DateTimeOffset.Now.TimeOfDay);
            await Task.Delay(1000, stoppingToken).ConfigureAwait(false);
        }
    }
}
