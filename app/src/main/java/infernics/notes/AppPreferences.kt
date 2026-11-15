package infernics.notes

import android.content.Context

object AppPreferences {
    private const val FILE_NAME = "secnote_preferences"
    private const val KEY_DARK_THEME = "dark_theme"
    private const val KEY_SCREENSHOT_BLOCKING = "screenshot_blocking"
    private const val KEY_AUTO_LOCK_MINUTES = "auto_lock_minutes"

    fun isDarkTheme(context: Context): Boolean =
        preferences(context).getBoolean(KEY_DARK_THEME, true)

    fun setDarkTheme(context: Context, enabled: Boolean) {
        preferences(context).edit().putBoolean(KEY_DARK_THEME, enabled).apply()
    }

    fun isScreenshotBlockingEnabled(context: Context): Boolean =
        preferences(context).getBoolean(KEY_SCREENSHOT_BLOCKING, false)

    fun setScreenshotBlockingEnabled(context: Context, enabled: Boolean) {
        preferences(context).edit().putBoolean(KEY_SCREENSHOT_BLOCKING, enabled).apply()
    }

    /** 0 = immediately, 1 = after one minute, 5 = after five minutes. */
    fun getAutoLockMinutes(context: Context): Int =
        preferences(context).getInt(KEY_AUTO_LOCK_MINUTES, 0).let { value ->
            if (value in setOf(0, 1, 5)) value else 0
        }

    fun setAutoLockMinutes(context: Context, minutes: Int) {
        require(minutes in setOf(0, 1, 5))
        preferences(context).edit().putInt(KEY_AUTO_LOCK_MINUTES, minutes).apply()
    }

    fun reset(context: Context) {
        preferences(context).edit().clear().commit()
    }

    private fun preferences(context: Context) =
        context.getSharedPreferences(FILE_NAME, Context.MODE_PRIVATE)
}
