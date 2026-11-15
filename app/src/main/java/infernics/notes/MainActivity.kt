package infernics.notes

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.view.WindowCompat
import androidx.fragment.app.FragmentActivity
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckBox
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Image as ImageIcon
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : FragmentActivity() {
    // Temporary system authentication/document-picker UI is an intentional user action.
    // The vault stays unlocked only until its result callback; ordinary backgrounding locks it.
    @Volatile var allowTemporarySystemUi: Boolean = false
    @Volatile var stoppedDuringTemporarySystemUi: Boolean = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (AppPreferences.isScreenshotBlockingEnabled(this)) {
            window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        }
        setContent { SecNoteApp(this) }
    }
}

@Composable
private fun SecNoteApp(activity: MainActivity) {
    val context = LocalContext.current
    var crypto by remember { mutableStateOf<Crypto?>(null) }
    var needsSetup by remember { mutableStateOf(!Vault.isSetup(context)) }
    var darkTheme by remember { mutableStateOf(AppPreferences.isDarkTheme(context)) }
    var biometricEnabled by remember { mutableStateOf(BiometricVault.isEnabled(context)) }
    var screenshotBlockingEnabled by remember {
        mutableStateOf(AppPreferences.isScreenshotBlockingEnabled(context))
    }

    // Existing automatic lock: erase the in-memory vault key when the app goes to background.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_STOP -> {
                    if (activity.allowTemporarySystemUi) {
                        activity.stoppedDuringTemporarySystemUi = true
                    } else {
                        crypto = null
                    }
                }
                Lifecycle.Event.ON_RESUME -> {
                    if (activity.stoppedDuringTemporarySystemUi && !activity.allowTemporarySystemUi) {
                        activity.stoppedDuringTemporarySystemUi = false
                        crypto = null
                    }
                }
                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    val scheme = if (darkTheme) secNoteDarkColors() else secNoteLightColors()
    SideEffect {
        val barColor = scheme.background.toArgb()
        activity.window.statusBarColor = barColor
        activity.window.navigationBarColor = barColor
        WindowCompat.getInsetsController(activity.window, activity.window.decorView).apply {
            isAppearanceLightStatusBars = !darkTheme
            isAppearanceLightNavigationBars = !darkTheme
        }
        if (screenshotBlockingEnabled) {
            activity.window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            activity.window.clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    MaterialTheme(
        colorScheme = scheme,
        typography = Typography(
            titleLarge = TextStyle(fontSize = 22.sp, fontFamily = FontFamily.SansSerif),
            titleMedium = TextStyle(fontSize = 17.sp, fontFamily = FontFamily.SansSerif)
        )
    ) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            val currentCrypto = crypto
            if (currentCrypto == null) {
                if (needsSetup) {
                    SetupScreen(onCreated = {
                        crypto = it
                        needsSetup = false
                    })
                } else {
                    LockScreen(
                        biometricEnabled = biometricEnabled,
                        onUnlocked = { crypto = it },
                        onBiometricUnlock = { report ->
                            BiometricVault.unlock(
                                activity,
                                onUnlocked = { unlocked -> crypto = unlocked },
                                onError = { message ->
                                    biometricEnabled = BiometricVault.isEnabled(context)
                                    report(message)
                                }
                            )
                        }
                    )
                }
            } else {
                MainScreen(
                    activity = activity,
                    crypto = currentCrypto,
                    darkTheme = darkTheme,
                    biometricEnabled = biometricEnabled,
                    screenshotBlockingEnabled = screenshotBlockingEnabled,
                    onLock = { crypto = null },
                    onThemeChange = { enabled ->
                        darkTheme = enabled
                        AppPreferences.setDarkTheme(context, enabled)
                    },
                    onScreenshotBlockingChange = { enabled ->
                        screenshotBlockingEnabled = enabled
                        AppPreferences.setScreenshotBlockingEnabled(context, enabled)
                    },
                    onBiometricChange = { enabled, report ->
                        if (enabled) {
                            BiometricVault.enable(
                                activity,
                                currentCrypto,
                                onEnabled = {
                                    biometricEnabled = true
                                    report("Вход по биометрии включён.")
                                },
                                onError = { message ->
                                    val lockAfterPrompt = activity.stoppedDuringTemporarySystemUi
                                    activity.stoppedDuringTemporarySystemUi = false
                                    if (lockAfterPrompt) crypto = null
                                    report(message)
                                }
                            )
                        } else {
                            BiometricVault.disable(context)
                            biometricEnabled = false
                            report("Вход по биометрии отключён. Основной пароль продолжает работать.")
                        }
                    }
                )
            }
        }
    }
}

private fun secNoteDarkColors() = darkColorScheme(
    primary = Color(0xFFC5C8CC),
    onPrimary = Color(0xFF17191B),
    primaryContainer = Color(0xFF303438),
    onPrimaryContainer = Color(0xFFE5E7E9),
    secondary = Color(0xFFB8BDC1),
    onSecondary = Color(0xFF1B1D1F),
    secondaryContainer = Color(0xFF292D31),
    onSecondaryContainer = Color(0xFFE0E3E5),
    tertiary = Color(0xFFADB3B8),
    onTertiary = Color(0xFF191B1D),
    background = Color(0xFF101112),
    onBackground = Color(0xFFF1F1F1),
    surface = Color(0xFF151719),
    onSurface = Color(0xFFF1F1F1),
    surfaceVariant = Color(0xFF202326),
    onSurfaceVariant = Color(0xFFB5B9BD),
    outline = Color(0xFF42474B),
    outlineVariant = Color(0xFF303438),
    error = Color(0xFFD6A09B),
    onError = Color(0xFF351F1D)
)

private fun secNoteLightColors() = lightColorScheme(
    primary = Color(0xFF51585E),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFE0E3E5),
    onPrimaryContainer = Color(0xFF252A2E),
    secondary = Color(0xFF62696F),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFE8EAEC),
    onSecondaryContainer = Color(0xFF292E32),
    tertiary = Color(0xFF686E73),
    onTertiary = Color.White,
    background = Color(0xFFF2F3F3),
    onBackground = Color(0xFF202326),
    surface = Color(0xFFFAFAFA),
    onSurface = Color(0xFF202326),
    surfaceVariant = Color(0xFFE6E8E9),
    onSurfaceVariant = Color(0xFF565D62),
    outline = Color(0xFF8D9499),
    outlineVariant = Color(0xFFD1D5D8),
    error = Color(0xFF8A3A34),
    onError = Color.White
)

@Composable
private fun SetupScreen(onCreated: (Crypto) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var repeatedPassword by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    Column(
        Modifier.fillMaxSize().padding(28.dp),
        verticalArrangement = Arrangement.Center
    ) {
        Text("SecNote", style = MaterialTheme.typography.headlineMedium)
        Text("infernics.ru", color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(30.dp))
        Text("Создайте основной пароль", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(8.dp))
        Text(
            "Он защищает заметки и файлы. Биометрический вход можно включить позже в настройках.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodyMedium
        )
        Spacer(Modifier.height(22.dp))
        OutlinedTextField(
            value = password,
            onValueChange = { password = it; errorMessage = null },
            label = { Text("Пароль (не менее 8 символов)") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(
            value = repeatedPassword,
            onValueChange = { repeatedPassword = it; errorMessage = null },
            label = { Text("Повторите пароль") },
            singleLine = true,
            isError = repeatedPassword.isNotEmpty() && password != repeatedPassword,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth()
        )
        if (errorMessage != null) {
            Spacer(Modifier.height(8.dp))
            Text(errorMessage!!, color = MaterialTheme.colorScheme.error)
        }
        Spacer(Modifier.height(22.dp))
        Button(
            onClick = {
                busy = true
                scope.launch {
                    val result = withContext(Dispatchers.Default) {
                        runCatching { Vault.create(context, password) }
                    }
                    busy = false
                    result.onSuccess(onCreated).onFailure {
                        errorMessage = it.message ?: "Не удалось создать хранилище"
                    }
                }
            },
            enabled = !busy && password.length >= 8 && password == repeatedPassword,
            modifier = Modifier.fillMaxWidth()
        ) {
            if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
            else Text("Создать защищённое хранилище")
        }
        Spacer(Modifier.height(14.dp))
        Text(
            "Пароль не сохраняется. Если вы его забудете, восстановить данные будет невозможно.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun LockScreen(
    biometricEnabled: Boolean,
    onUnlocked: (Crypto) -> Unit,
    onBiometricUnlock: ((String) -> Unit) -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    Column(
        Modifier.fillMaxSize().padding(28.dp),
        verticalArrangement = Arrangement.Center
    ) {
        Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(34.dp))
        Spacer(Modifier.height(14.dp))
        Text("SecNote", style = MaterialTheme.typography.headlineMedium)
        Text("infernics.ru", color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(28.dp))
        Text("Введите основной пароль", style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(16.dp))
        OutlinedTextField(
            value = password,
            onValueChange = { password = it; errorMessage = null },
            label = { Text("Пароль") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth()
        )
        if (errorMessage != null) {
            Spacer(Modifier.height(8.dp))
            Text(errorMessage!!, color = MaterialTheme.colorScheme.error)
        }
        Spacer(Modifier.height(16.dp))
        Button(
            onClick = {
                busy = true
                scope.launch {
                    val unlocked = withContext(Dispatchers.Default) { Vault.unlock(context, password) }
                    busy = false
                    if (unlocked == null) errorMessage = "Неверный пароль или повреждённое хранилище."
                    else onUnlocked(unlocked)
                }
            },
            enabled = !busy && password.isNotEmpty(),
            modifier = Modifier.fillMaxWidth()
        ) {
            if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
            else Text("Разблокировать паролем")
        }
        if (biometricEnabled) {
            Spacer(Modifier.height(10.dp))
            TextButton(
                onClick = { onBiometricUnlock { errorMessage = it } },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.Fingerprint, contentDescription = null)
                Spacer(Modifier.width(9.dp))
                Text("Войти по отпечатку")
            }
        }
    }
}

private enum class MainPage { NOTES, FILES, SETTINGS }

@Composable
private fun MainScreen(
    activity: MainActivity,
    crypto: Crypto,
    darkTheme: Boolean,
    biometricEnabled: Boolean,
    screenshotBlockingEnabled: Boolean,
    onLock: () -> Unit,
    onThemeChange: (Boolean) -> Unit,
    onScreenshotBlockingChange: (Boolean) -> Unit,
    onBiometricChange: (Boolean, (String) -> Unit) -> Unit
) {
    var page by remember { mutableStateOf(MainPage.NOTES) }
    BackHandler(enabled = page != MainPage.NOTES) { page = MainPage.NOTES }

    when (page) {
        MainPage.NOTES -> NotesHomeScreen(
            crypto = crypto,
            onOpenFiles = { page = MainPage.FILES },
            onOpenSettings = { page = MainPage.SETTINGS },
            onLock = onLock
        )
        MainPage.FILES -> FileVaultScreen(
            activity = activity,
            crypto = crypto,
            onBack = { page = MainPage.NOTES },
            onLock = onLock
        )
        MainPage.SETTINGS -> SettingsScreen(
            darkTheme = darkTheme,
            biometricEnabled = biometricEnabled,
            screenshotBlockingEnabled = screenshotBlockingEnabled,
            onThemeChange = onThemeChange,
            onScreenshotBlockingChange = onScreenshotBlockingChange,
            onBiometricChange = onBiometricChange,
            onBack = { page = MainPage.NOTES }
        )
    }
}

@Composable
private fun NotesHomeScreen(
    crypto: Crypto,
    onOpenFiles: () -> Unit,
    onOpenSettings: () -> Unit,
    onLock: () -> Unit
) {
    val context = LocalContext.current
    val repository = remember(crypto) { NoteRepository(context, crypto) }
    val scope = rememberCoroutineScope()
    var notes by remember { mutableStateOf<List<Note>>(emptyList()) }
    var loaded by remember { mutableStateOf(false) }
    var editing by remember { mutableStateOf<Note?>(null) }
    var editingIsNew by remember { mutableStateOf(true) }

    suspend fun reload() {
        notes = withContext(Dispatchers.IO) { repository.loadAll() }
        loaded = true
    }
    LaunchedEffect(crypto) { reload() }

    val current = editing
    if (current != null) {
        NoteEditorScreen(
            note = current,
            isNew = editingIsNew,
            onSaved = { changed ->
                scope.launch {
                    withContext(Dispatchers.IO) { repository.save(changed) }
                    reload()
                    editing = null
                }
            },
            onDeleted = { id ->
                scope.launch {
                    withContext(Dispatchers.IO) { repository.delete(id) }
                    reload()
                    editing = null
                }
            },
            onDiscard = { editing = null }
        )
    } else {
        NotesListScreen(
            notes = notes,
            loaded = loaded,
            onNew = { kind ->
                editing = Note(
                    kind = kind,
                    checklist = if (kind == NoteKind.LIST) listOf(ChecklistItem()) else emptyList()
                )
                editingIsNew = true
            },
            onOpen = { editing = it; editingIsNew = false },
            onOpenFiles = onOpenFiles,
            onOpenSettings = onOpenSettings,
            onLock = onLock
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun NotesListScreen(
    notes: List<Note>,
    loaded: Boolean,
    onNew: (NoteKind) -> Unit,
    onOpen: (Note) -> Unit,
    onOpenFiles: () -> Unit,
    onOpenSettings: () -> Unit,
    onLock: () -> Unit
) {
    var showCreateDialog by remember { mutableStateOf(false) }

    if (showCreateDialog) {
        AlertDialog(
            onDismissRequest = { showCreateDialog = false },
            title = { Text("Что создаём?") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = {
                            showCreateDialog = false
                            onNew(NoteKind.NOTE)
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Обычная заметка")
                    }
                    Button(
                        onClick = {
                            showCreateDialog = false
                            onNew(NoteKind.LIST)
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Список")
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = { showCreateDialog = false }) { Text("Отмена") }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("SecNote")
                        Text("infernics.ru", style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                },
                actions = {
                    IconButton(onClick = onOpenSettings) {
                        Icon(
                            Icons.Default.Settings,
                            contentDescription = "Настройки",
                            modifier = Modifier.size(24.dp)
                        )
                    }
                    IconButton(onClick = onOpenFiles) {
                        Icon(Icons.Default.FolderOpen, contentDescription = "Зашифрованные файлы")
                    }
                    IconButton(onClick = onLock) {
                        Icon(Icons.Default.Lock, contentDescription = "Заблокировать")
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { showCreateDialog = true }) {
                Icon(Icons.Default.Add, contentDescription = "Создать")
            }
        }
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                !loaded -> CircularProgressIndicator(Modifier.align(Alignment.Center))
                notes.isEmpty() -> Column(
                    Modifier.align(Alignment.Center).padding(32.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(Icons.Default.CheckBox, contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(38.dp))
                    Spacer(Modifier.height(12.dp))
                    Text("Пока нет записей", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text("Нажмите +, чтобы создать заметку или список.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodySmall)
                }
                else -> LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(horizontal = 16.dp, vertical = 10.dp),
                    verticalArrangement = Arrangement.spacedBy(9.dp)
                ) {
                    items(notes, key = { it.id }) { note ->
                        Card(
                            onClick = { onOpen(note) },
                            modifier = Modifier.fillMaxWidth(),
                            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant)
                        ) {
                            Column(Modifier.padding(horizontal = 16.dp, vertical = 14.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        note.title.ifBlank { if (note.kind == NoteKind.LIST) "Список" else "Без названия" },
                                        style = MaterialTheme.typography.titleMedium,
                                        modifier = Modifier.weight(1f)
                                    )
                                    Text(
                                        if (note.kind == NoteKind.LIST) "СПИСОК" else "ЗАМЕТКА",
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                val preview = if (note.kind == NoteKind.LIST) {
                                    val tasks = note.checklist.filter { it.text.isNotBlank() }
                                    if (tasks.isEmpty()) "Пустой список"
                                    else "${tasks.count { it.checked }}/${tasks.size} выполнено"
                                } else {
                                    note.body.trim()
                                }
                                if (preview.isNotBlank()) {
                                    Spacer(Modifier.height(5.dp))
                                    Text(preview, maxLines = 2,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        style = MaterialTheme.typography.bodyMedium)
                                }
                                Spacer(Modifier.height(8.dp))
                                Text(
                                    SimpleDateFormat("d MMM yyyy · HH:mm", Locale("ru")).format(Date(note.updatedAt)),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun NoteEditorScreen(
    note: Note,
    isNew: Boolean,
    onSaved: (Note) -> Unit,
    onDeleted: (String) -> Unit,
    onDiscard: () -> Unit
) {
    var title by remember(note.id) { mutableStateOf(note.title) }
    var body by remember(note.id) { mutableStateOf(note.body) }
    var checklist by remember(note.id) {
        mutableStateOf(
            if (note.kind == NoteKind.LIST) {
                // Migrate an old optional list description into the first inline checkbox row.
                val legacyBody = note.body.trim()
                when {
                    legacyBody.isNotEmpty() -> listOf(ChecklistItem(text = legacyBody)) + note.checklist
                    note.checklist.isEmpty() -> listOf(ChecklistItem())
                    else -> note.checklist
                }
            } else note.checklist
        )
    }
    var focusNextId by remember(note.id) { mutableStateOf<String?>(null) }
    var askDelete by remember { mutableStateOf(false) }
    val isList = note.kind == NoteKind.LIST
    val visibleTasks = checklist.filter { it.text.isNotBlank() }

    fun appendChecklistRow() {
        val newItem = ChecklistItem()
        checklist = checklist + newItem
        focusNextId = newItem.id
    }

    fun saveAndExit() {
        val savedChecklist = if (isList) checklist.filter { it.text.isNotBlank() } else emptyList()
        val savedBody = if (isList) "" else body
        val hasContent = if (isList) savedChecklist.isNotEmpty() else savedBody.isNotBlank()
        val blank = isNew && title.isBlank() && !hasContent
        if (blank) {
            onDiscard()
            return
        }
        val changed = title != note.title || savedBody != note.body || savedChecklist != note.checklist
        onSaved(
            note.copy(
                title = title.trim(),
                body = savedBody,
                checklist = savedChecklist,
                updatedAt = if (changed) System.currentTimeMillis() else note.updatedAt
            )
        )
    }

    BackHandler { saveAndExit() }
    if (askDelete) {
        AlertDialog(
            onDismissRequest = { askDelete = false },
            title = { Text(if (isList) "Удалить список?" else "Удалить заметку?") },
            text = { Text("Это действие нельзя отменить.") },
            confirmButton = {
                TextButton(onClick = { askDelete = false; onDeleted(note.id) }) { Text("Удалить") }
            },
            dismissButton = {
                TextButton(onClick = { askDelete = false }) { Text("Отмена") }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        when {
                            isNew && isList -> "Новый список"
                            isNew -> "Новая заметка"
                            isList -> "Редактирование списка"
                            else -> "Редактирование заметки"
                        }
                    )
                },
                navigationIcon = {
                    IconButton(onClick = ::saveAndExit) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Назад")
                    }
                },
                actions = {
                    if (!isNew) {
                        IconButton(onClick = { askDelete = true }) {
                            Icon(Icons.Default.Delete, contentDescription = "Удалить")
                        }
                    }
                }
            )
        }
    ) { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState())
                .padding(horizontal = 18.dp, vertical = 10.dp)
        ) {
            OutlinedTextField(
                value = title,
                onValueChange = { title = it },
                label = { Text(if (isList) "Название списка" else "Заголовок") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            if (!isList) {
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = body,
                    onValueChange = { body = it },
                    label = { Text("Текст заметки") },
                    minLines = 7,
                    modifier = Modifier.fillMaxWidth()
                )
            } else {
                Spacer(Modifier.height(10.dp))
                checklist.forEach { item ->
                    key(item.id) {
                        InlineChecklistRow(
                            item = item,
                            requestFocus = focusNextId == item.id,
                            onFocusHandled = { if (focusNextId == item.id) focusNextId = null },
                            onTextChange = { newText ->
                                checklist = checklist.map { current ->
                                    if (current.id == item.id) current.copy(text = newText) else current
                                }
                            },
                            onCheckedChange = { checked ->
                                checklist = checklist.map { current ->
                                    if (current.id == item.id) current.copy(checked = checked) else current
                                }
                            },
                            onNext = ::appendChecklistRow,
                            onDelete = { checklist = checklist.filterNot { it.id == item.id } }
                        )
                    }
                }
                TextButton(
                    onClick = ::appendChecklistRow,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Новая строка")
                }
                if (visibleTasks.isNotEmpty()) {
                    Text(
                        "${visibleTasks.count { it.checked }} из ${visibleTasks.size} выполнено",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(start = 8.dp, top = 2.dp)
                    )
                }
            }

            Spacer(Modifier.height(22.dp))
            Button(onClick = ::saveAndExit, modifier = Modifier.fillMaxWidth()) {
                Text(if (isList) "Сохранить список" else "Сохранить заметку")
            }
            Spacer(Modifier.height(12.dp))
        }
    }
}

@Composable
private fun InlineChecklistRow(
    item: ChecklistItem,
    requestFocus: Boolean,
    onFocusHandled: () -> Unit,
    onTextChange: (String) -> Unit,
    onCheckedChange: (Boolean) -> Unit,
    onNext: () -> Unit,
    onDelete: () -> Unit
) {
    val requester = remember(item.id) { FocusRequester() }
    LaunchedEffect(requestFocus) {
        if (requestFocus) {
            requester.requestFocus()
            onFocusHandled()
        }
    }
    Row(
        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Checkbox(checked = item.checked, onCheckedChange = onCheckedChange)
        BasicTextField(
            value = item.text,
            onValueChange = onTextChange,
            singleLine = true,
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
            keyboardActions = KeyboardActions(onNext = { onNext() }),
            textStyle = MaterialTheme.typography.bodyLarge.copy(
                color = MaterialTheme.colorScheme.onSurface,
                textDecoration = if (item.checked) TextDecoration.LineThrough else TextDecoration.None
            ),
            modifier = Modifier.weight(1f).focusRequester(requester).padding(vertical = 12.dp),
            decorationBox = { innerTextField ->
                Box(Modifier.fillMaxWidth()) {
                    if (item.text.isEmpty()) {
                        Text(
                            "Новая строка",
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    innerTextField()
                }
            }
        )
        IconButton(onClick = onDelete, modifier = Modifier.size(38.dp)) {
            Icon(
                Icons.Default.Delete,
                contentDescription = "Удалить строку",
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(18.dp)
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SettingsScreen(
    darkTheme: Boolean,
    biometricEnabled: Boolean,
    screenshotBlockingEnabled: Boolean,
    onThemeChange: (Boolean) -> Unit,
    onScreenshotBlockingChange: (Boolean) -> Unit,
    onBiometricChange: (Boolean, (String) -> Unit) -> Unit,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val biometricStatus = remember { BiometricVault.canAuthenticate(context) }
    var message by remember { mutableStateOf<String?>(null) }
    val biometricAvailable = biometricStatus == androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Настройки") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Назад")
                    }
                }
            )
        }
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).padding(20.dp).verticalScroll(rememberScrollState())) {
            Text("SecNote · версия 1.3", style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text("Пакет: infernics.notes", style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(22.dp))
            Text("Внешний вид", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            SettingRow(
                title = "Тёмная тема",
                subtitle = if (darkTheme) "Используется графитовая тема" else "Используется светлая нейтральная тема"
            ) {
                Switch(checked = darkTheme, onCheckedChange = onThemeChange)
            }
            Spacer(Modifier.height(26.dp))
            Text("Безопасность", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            SettingRow(
                title = "Вход по отпечатку",
                subtitle = when {
                    biometricEnabled -> "Включён. Основной пароль остаётся доступен."
                    biometricAvailable -> "Можно разблокировать приложение отпечатком или другим поддерживаемым сильным способом Android."
                    biometricStatus == androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
                        "Сначала добавьте отпечаток или биометрию в настройках Android."
                    else -> "На устройстве нет доступной сильной биометрии."
                }
            ) {
                Switch(
                    checked = biometricEnabled,
                    enabled = biometricAvailable || biometricEnabled,
                    onCheckedChange = { enabled -> onBiometricChange(enabled) { message = it } }
                )
            }
            if (message != null) {
                Spacer(Modifier.height(8.dp))
                Text(message!!, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall)
            }
            Spacer(Modifier.height(18.dp))
            SettingRow(
                title = "Блокировка скриншотов",
                subtitle = if (screenshotBlockingEnabled)
                    "Снимки экрана и запись экрана заблокированы для окна приложения"
                else "Снимки экрана разрешены"
            ) {
                Switch(
                    checked = screenshotBlockingEnabled,
                    onCheckedChange = onScreenshotBlockingChange
                )
            }
            Spacer(Modifier.height(25.dp))
            Text("Автоблокировка", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            Text(
                "Уже включена: при сворачивании приложения ключ очищается из памяти, и для повторного входа требуется пароль или включённая биометрия.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodyMedium
            )
            Spacer(Modifier.height(25.dp))
            Text("Хранилище", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            Text(
                "Заметки и файлы хранятся в зашифрованном виде в приватной памяти приложения.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodyMedium
            )
        }
    }
}

@Composable
private fun SettingRow(
    title: String,
    subtitle: String,
    control: @Composable () -> Unit
) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 9.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f).padding(end = 14.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            Spacer(Modifier.height(3.dp))
            Text(subtitle, color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall)
        }
        control()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FileVaultScreen(
    activity: MainActivity,
    crypto: Crypto,
    onBack: () -> Unit,
    onLock: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val repository = remember(crypto) { FileVaultRepository(context, crypto) }
    var files by remember { mutableStateOf<List<VaultFile>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var pendingExport by remember { mutableStateOf<VaultFile?>(null) }
    var deleteTarget by remember { mutableStateOf<VaultFile?>(null) }
    var previewTarget by remember { mutableStateOf<VaultFile?>(null) }
    var pendingImportUri by remember { mutableStateOf<Uri?>(null) }
    var lockAfterPendingImport by remember { mutableStateOf(false) }
    var selectedIds by remember { mutableStateOf<Set<String>>(emptySet()) }
    var selectionMode by remember { mutableStateOf(false) }
    var confirmBatchDelete by remember { mutableStateOf(false) }
    var pendingBatchExportIds by remember { mutableStateOf<List<String>>(emptyList()) }

    suspend fun reload() {
        files = withContext(Dispatchers.IO) { repository.loadAll() }
        selectedIds = selectedIds.intersect(files.map { it.id }.toSet())
        if (files.isEmpty()) selectionMode = false
        loading = false
    }

    fun toggleSelection(id: String) {
        selectedIds = if (id in selectedIds) selectedIds - id else selectedIds + id
        selectionMode = true
    }

    fun finishTemporaryPicker(lockAfterPicker: Boolean) {
        activity.allowTemporarySystemUi = false
        activity.stoppedDuringTemporarySystemUi = false
        if (lockAfterPicker) onLock()
    }

    LaunchedEffect(crypto) { reload() }

    // Ask for read + write access because importing now also attempts best-effort
    // overwrite/delete of the source after an encrypted copy is committed.
    val importLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        activity.allowTemporarySystemUi = false
        val lockAfterPicker = activity.stoppedDuringTemporarySystemUi
        activity.stoppedDuringTemporarySystemUi = false
        val uri = if (result.resultCode == Activity.RESULT_OK) result.data?.data else null
        if (uri != null) {
            val flags = (result.data?.flags ?: 0) and
                (Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
            if (flags != 0) {
                runCatching { context.contentResolver.takePersistableUriPermission(uri, flags) }
            }
            pendingImportUri = uri
            lockAfterPendingImport = lockAfterPicker
        } else if (lockAfterPicker) {
            onLock()
        }
    }

    val exportLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        activity.allowTemporarySystemUi = false
        val lockAfterPicker = activity.stoppedDuringTemporarySystemUi
        activity.stoppedDuringTemporarySystemUi = false
        val item = pendingExport
        pendingExport = null
        if (uri != null && item != null) {
            busy = true
            message = null
            scope.launch {
                val result = withContext(Dispatchers.IO) { runCatching { repository.export(item.id, uri) } }
                busy = false
                result.onSuccess { message = "Файл расшифрован и сохранён в выбранное место." }
                    .onFailure { message = "Не удалось экспортировать файл: ${it.message ?: "ошибка записи"}" }
                reload()
                if (lockAfterPicker) onLock()
            }
        } else if (lockAfterPicker) {
            onLock()
        }
    }

    val treeLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree()
    ) { treeUri ->
        activity.allowTemporarySystemUi = false
        val lockAfterPicker = activity.stoppedDuringTemporarySystemUi
        activity.stoppedDuringTemporarySystemUi = false
        val ids = pendingBatchExportIds
        pendingBatchExportIds = emptyList()
        if (treeUri != null && ids.isNotEmpty()) {
            val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            runCatching { context.contentResolver.takePersistableUriPermission(treeUri, flags) }
            busy = true
            message = null
            scope.launch {
                val result = withContext(Dispatchers.IO) {
                    runCatching { repository.exportManyToTree(ids, treeUri) }
                }
                busy = false
                result.onSuccess { batch ->
                    message = buildString {
                        append("Расшифровано: ${batch.exported}.")
                        if (batch.failedNames.isNotEmpty()) {
                            append(" Не удалось: ${batch.failedNames.joinToString()}")
                        }
                    }
                }.onFailure { message = "Ошибка массовой расшифровки: ${it.message ?: "неизвестная ошибка"}" }
                selectedIds = emptySet()
                selectionMode = false
                if (lockAfterPicker) onLock()
            }
        } else if (lockAfterPicker) {
            onLock()
        }
    }

    fun requestExport(item: VaultFile) {
        pendingExport = item
        activity.allowTemporarySystemUi = true
        exportLauncher.launch(item.name)
    }

    fun requestBatchExport() {
        if (selectedIds.isEmpty()) return
        pendingBatchExportIds = selectedIds.toList()
        activity.allowTemporarySystemUi = true
        treeLauncher.launch(null)
    }

    // The import dialog makes the destructive source-file operation explicit.
    pendingImportUri?.let { uri ->
        AlertDialog(
            onDismissRequest = {
                pendingImportUri = null
                finishTemporaryPicker(lockAfterPendingImport)
            },
            title = { Text("Переместить файл в защищённое хранилище?") },
            text = {
                Text(
                    "SecNote сначала создаст и проверит зашифрованную копию. Затем приложение попробует " +
                        "перезаписать исходный файл нулями и удалить его. Если провайдер не разрешит запись " +
                        "или удаление, оригинал может остаться. На SSD/flash-памяти и в облачных хранилищах " +
                        "физическое уничтожение прежних блоков гарантировать нельзя."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    pendingImportUri = null
                    busy = true
                    message = null
                    scope.launch {
                        val result = withContext(Dispatchers.IO) {
                            runCatching { repository.importAndRemoveOriginal(uri) }
                        }
                        busy = false
                        result.onSuccess { imported ->
                            message = when {
                                imported.originalOverwritten && imported.originalDeleted ->
                                    "Файл зашифрован. Исходник перезаписан на уровне провайдера и удалён; физическое стирание не гарантируется."
                                imported.originalDeleted ->
                                    "Файл зашифрован. Провайдер удалил оригинал, но перезапись подтвердить не удалось."
                                imported.originalOverwritten ->
                                    "Файл зашифрован. Исходник перезаписан, но провайдер не подтвердил удаление. Проверьте исходную папку."
                                else ->
                                    "Зашифрованная копия создана, но исходник не удалось перезаписать или удалить. Удалите его вручную из исходного приложения."
                            }
                            reload()
                        }.onFailure {
                            message = "Не удалось зашифровать файл: ${it.message ?: "ошибка чтения"}. Оригинал не удалялся."
                        }
                        finishTemporaryPicker(lockAfterPendingImport)
                        lockAfterPendingImport = false
                    }
                }) { Text("Зашифровать и удалить оригинал") }
            },
            dismissButton = {
                TextButton(onClick = {
                    pendingImportUri = null
                    finishTemporaryPicker(lockAfterPendingImport)
                    lockAfterPendingImport = false
                }) { Text("Отмена") }
            }
        )
    }

    if (deleteTarget != null) {
        val item = deleteTarget!!
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text("Удалить файл из хранилища?") },
            text = { Text("Зашифрованная копия «${item.name}» будет удалена.") },
            confirmButton = {
                TextButton(onClick = {
                    deleteTarget = null
                    if (previewTarget?.id == item.id) previewTarget = null
                    busy = true
                    scope.launch {
                        withContext(Dispatchers.IO) { repository.delete(item.id) }
                        reload()
                        busy = false
                    }
                }) { Text("Удалить") }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) { Text("Отмена") }
            }
        )
    }

    if (confirmBatchDelete) {
        AlertDialog(
            onDismissRequest = { confirmBatchDelete = false },
            title = { Text("Удалить выбранные файлы?") },
            text = { Text("Будет удалено зашифрованных объектов: ${selectedIds.size}. Это действие нельзя отменить.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmBatchDelete = false
                    val ids = selectedIds.toList()
                    busy = true
                    scope.launch {
                        val removed = withContext(Dispatchers.IO) { repository.deleteMany(ids) }
                        selectedIds = emptySet()
                        selectionMode = false
                        reload()
                        busy = false
                        message = "Удалено из защищённого хранилища: $removed."
                    }
                }) { Text("Удалить") }
            },
            dismissButton = { TextButton(onClick = { confirmBatchDelete = false }) { Text("Отмена") } }
        )
    }

    previewTarget?.let { item ->
        VaultImagePreviewDialog(
            item = item,
            repository = repository,
            onDismiss = { previewTarget = null },
            onExport = { previewTarget = null; requestExport(item) },
            onDelete = { previewTarget = null; deleteTarget = item }
        )
    }

    val imageFiles = files.filter { it.isImageFile() }
    val otherFiles = files.filterNot { it.isImageFile() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    if (selectionMode) Text("Выбрано: ${selectedIds.size}") else Column {
                        Text("Файловое хранилище")
                        Text("Файлы шифруются отдельно от заметок",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                },
                navigationIcon = {
                    IconButton(onClick = {
                        if (selectionMode) {
                            selectedIds = emptySet()
                            selectionMode = false
                        } else onBack()
                    }) {
                        Icon(Icons.Default.ArrowBack,
                            contentDescription = if (selectionMode) "Отменить выбор" else "К заметкам")
                    }
                },
                actions = {
                    if (selectionMode) {
                        IconButton(onClick = { selectedIds = files.map { it.id }.toSet() }) {
                            Icon(Icons.Default.CheckBox, contentDescription = "Выбрать все")
                        }
                        IconButton(onClick = ::requestBatchExport, enabled = selectedIds.isNotEmpty()) {
                            Icon(Icons.Default.SaveAlt, contentDescription = "Расшифровать выбранные")
                        }
                        IconButton(onClick = { confirmBatchDelete = true }, enabled = selectedIds.isNotEmpty()) {
                            Icon(Icons.Default.Delete, contentDescription = "Удалить выбранные")
                        }
                    } else if (files.isNotEmpty()) {
                        IconButton(onClick = { selectionMode = true }) {
                            Icon(Icons.Default.CheckBox, contentDescription = "Выбрать файлы")
                        }
                    }
                    if (!selectionMode) {
                        IconButton(onClick = onLock) {
                            Icon(Icons.Default.Lock, contentDescription = "Заблокировать")
                        }
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = {
                    val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                        addCategory(Intent.CATEGORY_OPENABLE)
                        type = "*/*"
                        addFlags(
                            Intent.FLAG_GRANT_READ_URI_PERMISSION or
                                Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
                        )
                    }
                    activity.allowTemporarySystemUi = true
                    importLauncher.launch(intent)
                }
            ) {
                Icon(Icons.Default.Add, contentDescription = "Добавить файл")
            }
        }
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            if (message != null) {
                Text(
                    message!!,
                    modifier = Modifier.padding(horizontal = 18.dp, vertical = 7.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall
                )
            }
            when {
                loading || busy -> Box(Modifier.fillMaxWidth().weight(1f), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }
                files.isEmpty() -> Box(Modifier.fillMaxWidth().weight(1f), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(28.dp)) {
                        Icon(Icons.Default.FolderOpen, contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.size(38.dp))
                        Spacer(Modifier.height(10.dp))
                        Text("Хранилище пусто")
                        Text("Добавьте фото или документ кнопкой ниже.",
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            style = MaterialTheme.typography.bodySmall)
                    }
                }
                else -> LazyColumn(
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(horizontal = 14.dp, vertical = 10.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    if (imageFiles.isNotEmpty()) {
                        item {
                            Text("Фотографии", style = MaterialTheme.typography.titleMedium,
                                modifier = Modifier.padding(start = 2.dp, top = 4.dp, bottom = 2.dp))
                        }
                        items(imageFiles.chunked(3), key = { row -> "images-${row.first().id}" }) { rowFiles ->
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(9.dp)
                            ) {
                                rowFiles.forEach { item ->
                                    VaultImageTile(
                                        item = item,
                                        repository = repository,
                                        modifier = Modifier.weight(1f),
                                        selected = item.id in selectedIds,
                                        selectionMode = selectionMode,
                                        onToggleSelection = { toggleSelection(item.id) },
                                        onLongSelect = { toggleSelection(item.id) },
                                        onPreview = { previewTarget = item },
                                        onExport = { requestExport(item) },
                                        onDelete = { deleteTarget = item }
                                    )
                                }
                                repeat(3 - rowFiles.size) { Spacer(Modifier.weight(1f)) }
                            }
                        }
                    }
                    if (otherFiles.isNotEmpty()) {
                        item {
                            Text(
                                "Файлы и документы",
                                style = MaterialTheme.typography.titleMedium,
                                modifier = Modifier.padding(start = 2.dp, top = if (imageFiles.isEmpty()) 4.dp else 14.dp, bottom = 2.dp)
                            )
                        }
                        items(otherFiles, key = { it.id }) { item ->
                            VaultDocumentRow(
                                item = item,
                                selected = item.id in selectedIds,
                                selectionMode = selectionMode,
                                onToggleSelection = { toggleSelection(item.id) },
                                onLongSelect = { toggleSelection(item.id) },
                                onExport = { requestExport(item) },
                                onDelete = { deleteTarget = item }
                            )
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun VaultImageTile(
    item: VaultFile,
    repository: FileVaultRepository,
    modifier: Modifier = Modifier,
    selected: Boolean,
    selectionMode: Boolean,
    onToggleSelection: () -> Unit,
    onLongSelect: () -> Unit,
    onPreview: () -> Unit,
    onExport: () -> Unit,
    onDelete: () -> Unit
) {
    val thumbnail by androidx.compose.runtime.produceState<android.graphics.Bitmap?>(
        null,
        item.id,
        repository
    ) {
        value = withContext(Dispatchers.IO) { repository.loadThumbnail(item.id, 420) }
    }

    Card(
        modifier = modifier.combinedClickable(
            onClick = { if (selectionMode) onToggleSelection() else onPreview() },
            onLongClick = onLongSelect
        ),
        border = BorderStroke(
            if (selected) 2.dp else 1.dp,
            if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant
        )
    ) {
        Column(Modifier.padding(5.dp)) {
            Box(
                modifier = Modifier.fillMaxWidth().aspectRatio(1f)
                    .clip(RoundedCornerShape(7.dp))
                    .background(MaterialTheme.colorScheme.surfaceVariant),
                contentAlignment = Alignment.Center
            ) {
                if (thumbnail != null) {
                    Image(
                        bitmap = thumbnail!!.asImageBitmap(),
                        contentDescription = item.name,
                        modifier = Modifier.fillMaxSize(),
                        contentScale = ContentScale.Crop
                    )
                } else {
                    Icon(ImageIcon, contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(30.dp))
                }
                if (selectionMode) {
                    Checkbox(
                        checked = selected,
                        onCheckedChange = { onToggleSelection() },
                        modifier = Modifier.align(Alignment.TopEnd)
                            .background(MaterialTheme.colorScheme.surface.copy(alpha = 0.85f), RoundedCornerShape(50))
                    )
                }
            }
            Spacer(Modifier.height(5.dp))
            Text(item.name, maxLines = 1, style = MaterialTheme.typography.labelSmall)
            if (!selectionMode) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    IconButton(onClick = onExport, modifier = Modifier.size(34.dp)) {
                        Icon(Icons.Default.SaveAlt, contentDescription = "Экспортировать фото",
                            modifier = Modifier.size(18.dp))
                    }
                    IconButton(onClick = onDelete, modifier = Modifier.size(34.dp)) {
                        Icon(Icons.Default.Delete, contentDescription = "Удалить фото",
                            modifier = Modifier.size(18.dp))
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun VaultDocumentRow(
    item: VaultFile,
    selected: Boolean,
    selectionMode: Boolean,
    onToggleSelection: () -> Unit,
    onLongSelect: () -> Unit,
    onExport: () -> Unit,
    onDelete: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth().combinedClickable(
            onClick = { if (selectionMode) onToggleSelection() },
            onLongClick = onLongSelect
        ),
        border = BorderStroke(
            if (selected) 2.dp else 1.dp,
            if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant
        )
    ) {
        Row(
            Modifier.fillMaxWidth().padding(start = 10.dp, end = 4.dp, top = 7.dp, bottom = 7.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (selectionMode) {
                Checkbox(checked = selected, onCheckedChange = { onToggleSelection() })
            } else {
                Icon(Icons.Default.InsertDriveFile, contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.size(27.dp))
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(item.name, style = MaterialTheme.typography.bodyLarge, maxLines = 2)
                Text(
                    "${formatBytes(item.sizeBytes)} · ${SimpleDateFormat("d MMM yyyy", Locale("ru")).format(Date(item.addedAt))}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            if (!selectionMode) {
                IconButton(onClick = onExport) {
                    Icon(Icons.Default.SaveAlt, contentDescription = "Экспортировать файл")
                }
                IconButton(onClick = onDelete) {
                    Icon(Icons.Default.Delete, contentDescription = "Удалить файл")
                }
            }
        }
    }
}

@Composable
private fun VaultImagePreviewDialog(
    item: VaultFile,
    repository: FileVaultRepository,
    onDismiss: () -> Unit,
    onExport: () -> Unit,
    onDelete: () -> Unit
) {
    val bitmap by androidx.compose.runtime.produceState<android.graphics.Bitmap?>(
        null,
        item.id,
        repository
    ) {
        value = withContext(Dispatchers.IO) { repository.loadThumbnail(item.id, 1800) }
    }
    androidx.compose.ui.window.Dialog(onDismissRequest = onDismiss) {
        Surface(
            shape = RoundedCornerShape(16.dp),
            color = MaterialTheme.colorScheme.surface,
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(Modifier.padding(12.dp)) {
                Text(item.name, style = MaterialTheme.typography.titleMedium, maxLines = 2)
                Spacer(Modifier.height(10.dp))
                Box(
                    Modifier.fillMaxWidth().heightIn(max = 560.dp),
                    contentAlignment = Alignment.Center
                ) {
                    if (bitmap != null) {
                        Image(
                            bitmap = bitmap!!.asImageBitmap(),
                            contentDescription = item.name,
                            modifier = Modifier.fillMaxWidth().heightIn(max = 560.dp),
                            contentScale = ContentScale.Fit
                        )
                    } else {
                        CircularProgressIndicator()
                    }
                }
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                    TextButton(onClick = onDelete) { Text("Удалить") }
                    TextButton(onClick = onExport) { Text("Экспортировать") }
                    TextButton(onClick = onDismiss) { Text("Закрыть") }
                }
            }
        }
    }
}

private fun VaultFile.isImageFile(): Boolean {
    val mime = mimeType.lowercase(Locale.ROOT)
    if (mime.startsWith("image/")) return true
    return name.substringAfterLast('.', "").lowercase(Locale.ROOT) in setOf(
        "jpg", "jpeg", "png", "webp", "gif", "bmp", "heic", "heif", "avif"
    )
}

private fun formatBytes(value: Long): String = when {
    value < 1024 -> "$value Б"
    value < 1024L * 1024 -> "${String.format(Locale.US, "%.1f", value / 1024.0)} КБ"
    else -> "${String.format(Locale.US, "%.1f", value / (1024.0 * 1024.0))} МБ"
}
