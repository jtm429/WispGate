package com.example.wispgateclient

class PendingFileChooser<T> {
    var pending: ((T?) -> Unit)? = null
        private set

    fun replace(callback: (T?) -> Unit) {
        cancel()
        pending = callback
    }

    fun complete(value: T?) {
        val callback = pending
        pending = null
        callback?.invoke(value)
    }

    fun cancel() = complete(null)
}
