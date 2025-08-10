-- OpenSecurity complet v1 autonome (sans MineOS)
local component = require("component")
local event = require("event")
local serialization = require("serialization")
local filesystem = require("filesystem")
local computer = require("computer")
local unicode = require("unicode")
local os = require("os")
local term = require("term")

local crypto = component.crypto

-- CONSTANTES
local CONFIG_FILE = "/etc/opensecurity_config.cfg"
local HISTORY_FILE = "/etc/opensecurity_history.cfg"
local DISK_MOUNT = "/mnt/disk"
local DISK_CONFIG_FILE = DISK_MOUNT.."/config.txt"

local MAX_ATTEMPTS = 3
local LOCK_BASE_TIME = 30
local SCAN_INTERVAL = 3 -- secondes entre scans identiques
local SALT = "OpenSecSalt2025" -- sel pour hash

-- VARIABLES GLOBALES
local config = {
  users = {},
  admins = {},
  doors = {}, -- {controller=component_address, screen=screen_address, name=string}
  magneticCards = {}, -- cartes magnétiques avec verrouillage
}

local history = {}
local lastScanTimes = {}

-- GPU / écrans
local gpuByScreen = {}
local screens = {}
for addr in component.list("screen") do
  table.insert(screens, addr)
end
for _, screenAddr in ipairs(screens) do
  local gpuAddr = component.list("gpu", true)(screenAddr)
  gpuByScreen[screenAddr] = component.proxy(gpuAddr)
end

-- Buzzer optionnel
local buzzer = component.isAvailable("beep") and component.beepsound

-- UTILITAIRES

local function saveConfig(path)
  path = path or CONFIG_FILE
  local f, err = io.open(path, "w")
  if not f then
    print("Erreur sauvegarde config:", err)
    return false
  end
  f:write(serialization.serialize(config))
  f:close()
  return true
end

local function loadConfig()
  if filesystem.exists(CONFIG_FILE) then
    local f = io.open(CONFIG_FILE, "r")
    local data = f:read("*a")
    f:close()
    config = serialization.unserialize(data) or config
  end
end

local function saveHistory(path)
  path = path or HISTORY_FILE
  local f, err = io.open(path, "w")
  if not f then
    print("Erreur sauvegarde historique:", err)
    return false
  end
  f:write(serialization.serialize(history))
  f:close()
  return true
end

local function loadHistory()
  if filesystem.exists(HISTORY_FILE) then
    local f = io.open(HISTORY_FILE, "r")
    local data = f:read("*a")
    f:close()
    history = serialization.unserialize(data) or {}
  end
end

local function readDiskConfigPath()
  if filesystem.exists(DISK_CONFIG_FILE) then
    local f = io.open(DISK_CONFIG_FILE,"r")
    if f then
      local path = f:read("*l")
      f:close()
      if path and path ~= "" then
        return path
      end
    end
  end
  return nil
end

local function backupOnDisk()
  if filesystem.exists(DISK_MOUNT) then
    local path = readDiskConfigPath()
    if path then
      local fullConfigPath = path.."/opensecurity_config_backup.cfg"
      local fullHistoryPath = path.."/opensecurity_history_backup.cfg"
      if saveConfig(fullConfigPath) and saveHistory(fullHistoryPath) then
        print("Backup config et historique sauvegardés sur disquette.")
      else
        print("Erreur lors de la sauvegarde backup disquette.")
      end
    else
      print("Fichier config.txt introuvable ou vide sur disquette.")
    end
  else
    print("Disquette non montée.")
  end
end

local function hashPassword(pwd)
  if crypto then
    return crypto.digest("sha256", SALT .. pwd)
  else
    return pwd -- fallback non sécurisé
  end
end

local function isAdminCard(cardID)
  for _, c in ipairs(config.admins) do
    if c == cardID then return true end
  end
  return false
end

local function findUserByCard(cardID)
  for username, user in pairs(config.users) do
    for _, c in ipairs(user.rfid or {}) do
      if c == cardID then return username end
    end
    for _, c in ipairs(user.magnetic or {}) do
      if c == cardID then return username end
    end
  end
  return nil
end

local function isMagneticCardValid(cardID)
  for _, card in ipairs(config.magneticCards) do
    if card.name == cardID and card.locked then
      return true
    end
  end
  return false
end

local function logAccess(username, cardID, doorIndex, success)
  table.insert(history, {
    timestamp = os.time(),
    username = username or "inconnu",
    cardID = cardID or "inconnu",
    door = doorIndex or 0,
    success = success or false
  })
  saveHistory()
end

local function toMinutes(t)
  local h,m = t:match("(%d%d?):(%d%d)")
  return tonumber(h)*60 + tonumber(m)
end

local dayNames = {"sun","mon","tue","wed","thu","fri","sat"}

local function hasAccess(user, doorIndex)
  local allowed = false
  for _, d in ipairs(user.access or {}) do
    if d == doorIndex then allowed = true break end
  end
  if not allowed then return false end

  local schedule = user.schedule
  if not schedule then return true end

  local time = os.date("*t")
  local currentDay = dayNames[time.wday]

  if not schedule.days then return true end
  local dayAllowed = false
  for _, day in ipairs(schedule.days) do
    if day == currentDay then dayAllowed = true break end
  end
  if not dayAllowed then return false end

  local nowMinutes = time.hour*60 + time.min
  local startM = toMinutes(schedule.start)
  local endM = toMinutes(schedule["end"])

  return nowMinutes >= startM and nowMinutes <= endM
end

local function registerFailedAttempt(user)
  user.attempts = (user.attempts or 0) + 1
  if user.attempts >= MAX_ATTEMPTS then
    local lockTime = LOCK_BASE_TIME * 2^(user.attempts - MAX_ATTEMPTS)
    user.lockedUntil = os.time() + lockTime
  end
end

local function isScanAllowed(cardID)
  local now = os.time()
  if lastScanTimes[cardID] and (now - lastScanTimes[cardID] < SCAN_INTERVAL) then
    return false
  end
  lastScanTimes[cardID] = now
  return true
end

local function beep(success)
  if buzzer then
    if success then
      buzzer.beep(1000, 0.2)
    else
      buzzer.beep(400, 0.5)
    end
  end
end

-- UI fonctions

local function clearScreen(gpu)
  local w,h = gpu.getResolution()
  gpu.setBackground(0x1e1e2e)
  gpu.setForeground(0xc0c0c0)
  gpu.fill(1,1,w,h," ")
end

local function drawButton(gpu, x, y, w, h, text, fg, bg)
  fg = fg or 0xc0c0c0
  bg = bg or 0x4a4a7a
  gpu.setBackground(bg)
  gpu.fill(x, y, w, h, " ")
  gpu.setForeground(fg)
  local tx = x + math.floor((w - unicode.len(text)) / 2)
  local ty = y + math.floor(h / 2)
  gpu.set(tx, ty, text)
end

local function waitButtonClick(gpu, buttons)
  while true do
    local _, _, screen, x, y = event.pull("touch")
    if gpu.address == gpuByScreen[screen].address then
      for _, b in ipairs(buttons) do
        if x >= b.x and x <= b.x + b.w -1 and y >= b.y and y <= b.y + b.h -1 then
          return b.text
        end
      end
    end
  end
end

local function inputText(gpu, x, y, w, prompt, mask)
  clearScreen(gpu)
  gpu.setForeground(0xc0c0c0)
  gpu.setBackground(0x1e1e2e)
  gpu.set(x, y, prompt)
  local input = ""
  local pos = x + unicode.len(prompt)
  gpu.set(pos, y, "")
  while true do
    local _, _, _, _, _, key, _ = event.pull("key_down")
    if key == 13 then break
    elseif key == 8 then
      if #input > 0 then
        input = input:sub(1, -2)
        gpu.set(pos + #input, y, " ")
      end
    elseif key >= 32 and key <= 126 then
      if #input < w - unicode.len(prompt) then
        input = input .. string.char(key)
      end
    end
    local display = mask and string.rep("*", #input) or input
    gpu.set(pos, y, display .. (" "):rep(w - unicode.len(prompt) - #input))
  end
  return input
end

local function virtualKeyboard(gpu, x, y)
  local keys = {
    {"1","2","3"},
    {"4","5","6"},
    {"7","8","9"},
    {"<","0","OK"},
  }
  local input = ""
  while true do
    clearScreen(gpu)
    gpu.set(1,y-2,"Entrer code: "..input)
    for row=1,#keys do
      for col=1,#keys[row] do
        local key = keys[row][col]
        local bx = x + (col-1)*5
        local by = y + (row-1)*3
        drawButton(gpu, bx, by, 4, 2, key)
      end
    end
    local ev = {event.pull("touch")}
    local tx, ty = ev[4], ev[5]
    for row=1,#keys do
      for col=1,#keys[row] do
        local bx = x + (col-1)*5
        local by = y + (row-1)*3
        if tx >= bx and tx < bx+4 and ty >= by and ty < by+2 then
          local key = keys[row][col]
          if key == "<" then
            input = input:sub(1,-2)
          elseif key == "OK" then
            return input
          else
            input = input .. key
          end
        end
      end
    end
  end
end

local function showMessage(gpu, msg, duration)
  clearScreen(gpu)
  gpu.set(1,1,msg)
  computer.sleep(duration or 2)
end

-- Contrôle de la porte via Rolldoor (API standard)
local function openDoor(doorIndex)
  local door = config.doors[doorIndex]
  if not door or not door.controller then return false end
  local rolldoor = component.proxy(door.controller)
  if rolldoor and rolldoor.open and rolldoor.isOpen and rolldoor.close then
    if not rolldoor.isOpen() then
      rolldoor.open()
      computer.sleep(3) -- ouverture 3 secondes
      rolldoor.close()
    end
    return true
  end
  return false
end

-- Gestion création utilisateur sécurisée (scan carte admin)
local function createUserSecure(gpu)
  clearScreen(gpu)
  gpu.set(1,1,"Scan carte admin pour créer utilisateur")
  while true do
    local _,_,_,_,_,cardID = event.pull("rfid")
    if isAdminCard(cardID) then
      gpu.set(1,2,"Carte admin reconnue")
      adminAddUser(gpu)
      return
    else
      gpu.set(1,2,"Carte non autorisée")
    end
  end
end

-- Ajout utilisateur (via interface)
function adminAddUser(gpu)
  clearScreen(gpu)
  local username = inputText(gpu, 1, 2, 30, "Nom utilisateur : ", false)
  if config.users[username] then
    gpu.set(1,4,"Utilisateur existe déjà !")
    computer.sleep(2)
    return
  end
  local pwd1 = inputText(gpu, 1, 5, 30, "Mot de passe : ", true)
  local pwd2 = inputText(gpu, 1, 7, 30, "Confirmer mdp : ", true)
  if pwd1 ~= pwd2 then
    gpu.set(1,9,"Les mots de passe ne correspondent pas.")
    computer.sleep(2)
    return
  end
  config.users[username] = {
    hashpwd = hashPassword(pwd1),
    rfid = {},
    magnetic = {},
    access = {},
    schedule = nil,
    attempts = 0,
    lockedUntil = nil,
  }
  saveConfig()
  gpu.set(1,9,"Utilisateur ajouté avec succès.")
  computer.sleep(2)
end

-- Nouvelle fonction : ajout carte magnétique (sans écriture, avec code maître + nom)
local function addMagneticCardAdmin(gpu)
  clearScreen(gpu)
  gpu.set(1,1,"Code de sécurité maître :")
  local masterCode = inputText(gpu, 1, 2, 30, "Code : ", true)
  if masterCode ~= "maître y" then
    gpu.set(1,4,"Code maître incorrect")
    computer.sleep(2)
    return false
  end
  gpu.set(1,4,"Code maître validé.")
  computer.sleep(1)
  clearScreen(gpu)
  local cardName = inputText(gpu, 1, 2, 30, "Nom de la carte : ", false)
  if not cardName or cardName == "" then
    gpu.set(1,4,"Nom invalide")
    computer.sleep(2)
    return false
  end

  if not config.magneticCards then
    config.magneticCards = {}
  end
  table.insert(config.magneticCards, {name = cardName, locked = true})

  saveConfig()
  gpu.set(1,4,"Carte '"..cardName.."' ajoutée et verrouillée.")
  computer.sleep(2)
  return true
end

-- Gestion accès utilisateur (scan + mdp)
local function handleAccess(cardID, doorIndex, gpu)
  if not isScanAllowed(cardID) then
    showMessage(gpu, "Scan répété trop rapide !")
    beep(false)
    return false
  end
  local username = findUserByCard(cardID)
  if not username then
    showMessage(gpu, "Carte non reconnue")
    beep(false)
    logAccess(nil, cardID, doorIndex, false)
    return false
  end
  local user = config.users[username]
  local now = os.time()
  if user.lockedUntil and user.lockedUntil > now then
    showMessage(gpu, "Compte verrouillé, réessayez plus tard")
    beep(false)
    return false
  end
  if not hasAccess(user, doorIndex) then
    showMessage(gpu, "Pas d’accès à cette porte maintenant")
    logAccess(username, cardID, doorIndex, false)
    registerFailedAttempt(user)
    saveConfig()
    beep(false)
    return false
  end
  local pwd = virtualKeyboard(gpu, 2, 5)
  if hashPassword(pwd) ~= user.hashpwd then
    showMessage(gpu, "Mot de passe incorrect")
    registerFailedAttempt(user)
    saveConfig()
    logAccess(username, cardID, doorIndex, false)
    beep(false)
    return false
  end
  user.attempts = 0
  user.lockedUntil = nil
  saveConfig()
  logAccess(username, cardID, doorIndex, true)
  showMessage(gpu, "Accès autorisé, ouverture porte")
  beep(true)
  openDoor(doorIndex)
  return true
end

-- MENU ADMINISTATEUR

local function adminMenu(gpu)
  while true do
    clearScreen(gpu)
    local buttons = {
      {x=5,y=3,w=30,h=3,text="Ajouter utilisateur"},
      {x=5,y=7,w=30,h=3,text="Configurer portes"},
      {x=5,y=11,w=30,h=3,text="Ajouter carte magnétique"},
      {x=5,y=15,w=30,h=3,text="Voir historique"},
      {x=5,y=19,w=30,h=3,text="Quitter"},
    }
    for _,b in ipairs(buttons) do
      drawButton(gpu,b.x,b.y,b.w,b.h,b.text)
    end
    local choice = waitButtonClick(gpu, buttons)
    if choice == "Ajouter utilisateur" then
      createUserSecure(gpu)
    elseif choice == "Configurer portes" then
      configureDoors(gpu)
    elseif choice == "Ajouter carte magnétique" then
      addMagneticCardAdmin(gpu)
    elseif choice == "Voir historique" then
      showHistory(gpu)
    elseif choice == "Quitter" then
      break
    end
  end
end

-- Fonction configuration portes
function configureDoors(gpu)
  while true do
    clearScreen(gpu)
    gpu.set(1,1,"Configuration des portes")
    for i, door in ipairs(config.doors) do
      gpu.set(1, 2 + i, i .. ": " .. door.name)
    end
    gpu.set(1, 2 + #config.doors + 1, "[A]jouter une porte")
    gpu.set(1, 2 + #config.doors + 2, "[Q]uitter")
    local _, _, _, _, key = event.pull("key_down")
    if key == 34 or key == 65 then -- a ou A
      addDoor(gpu)
    elseif key == 16 or key == 81 then -- q 
