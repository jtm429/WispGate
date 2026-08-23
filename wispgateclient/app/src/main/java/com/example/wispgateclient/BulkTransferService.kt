package com.example.wispgateclient

import com.example.wispgateclient.wisp.*

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import java.util.concurrent.ConcurrentHashMap

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch

data class BulkTransferJob(
    val server: RelayClient.ServerInfo,
    val wisp: RelayClient.Wisp,
    val action: StagedFileAction,
)

object BulkTransferJobs {
    private val jobs = ConcurrentHashMap<String, BulkTransferJob>()

    fun put(job: BulkTransferJob) {
        require(jobs.putIfAbsent(job.action.transferId, job) == null) { "Transfer is already queued" }
    }

    fun take(transferId: String): BulkTransferJob? = jobs.remove(transferId)
}

data class BulkTransferResult(
    val transferId: String,
    val wispId: String,
    val state: RelayClient.WispState? = null,
    val error: String? = null,
)

class BulkTransferResultQueue {
    private val channel = Channel<BulkTransferResult>(Channel.UNLIMITED)
    val results = channel.receiveAsFlow()

    fun publish(result: BulkTransferResult): Boolean = channel.trySend(result).isSuccess
}

/** Keeps the service alive until the last concurrently started transfer releases ownership. */
class BulkTransferOwnership {
    private val active = mutableSetOf<String>()
    private var latestStartId = 0

    @Synchronized
    fun started(transferId: String, startId: Int) {
        require(active.add(transferId)) { "Transfer is already active" }
        latestStartId = maxOf(latestStartId, startId)
    }

    @Synchronized
    fun finished(transferId: String): Int? {
        active.remove(transferId)
        return latestStartId.takeIf { active.isEmpty() }
    }

    @Synchronized
    fun hasActiveTransfers(): Boolean = active.isNotEmpty()
}

object BulkTransferExecution {
    suspend fun <T> run(
        action: StagedFileAction,
        acquireWakeLock: () -> Unit,
        wakeLockHeld: () -> Boolean,
        releaseWakeLock: () -> Unit,
        transfer: suspend () -> T,
    ): T = try {
        acquireWakeLock()
        transfer()
    } finally {
        try {
            action.cleanup()
        } finally {
            if (wakeLockHeld()) releaseWakeLock()
        }
    }
}

class BulkTransferService : Service() {
    companion object {
        private const val CHANNEL_ID = "wispgate-transfers"
        private const val NOTIFICATION_ID = 7001
        private const val EXTRA_TRANSFER_ID = "transfer_id"
        private val resultQueue = BulkTransferResultQueue()
        val results = resultQueue.results

        private fun publishResult(result: BulkTransferResult) {
            if (!resultQueue.publish(result)) result.state?.cleanup()
        }

        fun enqueue(context: Context, job: BulkTransferJob) {
            BulkTransferJobs.put(job)
            try {
                ContextCompat.startForegroundService(
                    context,
                    Intent(context, BulkTransferService::class.java)
                        .putExtra(EXTRA_TRANSFER_ID, job.action.transferId),
                )
            } catch (cause: Throwable) {
                BulkTransferJobs.take(job.action.transferId)?.action?.cleanup()
                throw cause
            }
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val ownership = BulkTransferOwnership()

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "File transfers", NotificationManager.IMPORTANCE_LOW),
            )
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(
            NOTIFICATION_ID,
            NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_upload)
                .setContentTitle("WispGate file transfer")
                .setContentText("Encrypting and sending file")
                .setOngoing(true)
                .build(),
        )
        val transferId = intent?.getStringExtra(EXTRA_TRANSFER_ID)
        Log.i("WispFileTransfer", "service start startId=$startId transfer=$transferId hasIntent=${intent != null}")
        val job = transferId?.let(BulkTransferJobs::take)
        if (job == null) {
            Log.e("WispFileTransfer", "service job missing transfer=$transferId")
            if (!ownership.hasActiveTransfers()) stopSelf(startId)
            return START_NOT_STICKY
        }
        ownership.started(job.action.transferId, startId)
        Log.i("WispFileTransfer", "service job accepted transfer=${job.action.transferId} files=${job.action.files.size} wisp=${job.wisp.id}")
        scope.launch {
            val wakeLock = (getSystemService(Context.POWER_SERVICE) as PowerManager)
                .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "WispGate:BulkTransfer")
            try {
                val state = BulkTransferExecution.run(
                    action = job.action,
                    acquireWakeLock = { wakeLock.acquire(30 * 60_000L) },
                    wakeLockHeld = wakeLock::isHeld,
                    releaseWakeLock = wakeLock::release,
                ) {
                    RelayClient(applicationContext).sendFileAction(job.server, job.wisp, job.action)
                }
                publishResult(BulkTransferResult(job.action.transferId, job.wisp.id, state = state))
            } catch (cause: Throwable) {
                Log.e("WispFileTransfer", "transfer failed id=${job.action.transferId}: ${cause::class.java.simpleName}: ${cause.message}", cause)
                publishResult(
                    BulkTransferResult(
                        job.action.transferId,
                        job.wisp.id,
                        error = cause.message ?: "Unable to send Wisp file action",
                    ),
                )
            } finally {
                ownership.finished(job.action.transferId)?.let(::stopSelf)
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {

        scope.cancel()
        super.onDestroy()
    }
}
