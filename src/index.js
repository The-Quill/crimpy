#!/usr/bin/env node

const fs = require('fs')
const path = require('path')
const plist = require('plist')
const colors = require('colors')
const moment = require('moment')
const xml = require('xml-parser')
const { argv } = require('optimist')
const { exec } = require('child-process-promise')
const request = require('request-promise-native')
const fakeSequential = require('promise-sequential')
const pause = require('pause-js')
const SqliteToJson = require('sqlite-to-json')
const sqlite3 = require('sqlite3')

function jsonSqlite(filepath){
  const exporter = new SqliteToJson({
    client: new sqlite3.Database(filepath)
  })
  return new Promise((resolve, reject) => {
    exporter.all(function (err, all) {
      if (err) return reject(err)
      resolve(all)
    })
  })
}

function get(account){
  // console.log({
  //   account
  // })
  pause.millis(1000)
  return request({ uri: `https://haveibeenpwned.com/api/v2/breachedaccount/${account}`, headers: { 'User-Agent': 'OSX Recon Tool' }})
  .then(r => ({ [account]: JSON.parse(r) }))
  .catch(async e => {
    if (e.statusCode == 429){
      pause.millis(1300)
      return await get(account)
    } else if (e.statusCode == 404){
      return { [account]: [] }
    }
    console.error(`${account} failed: ${e.statusCode}`)
    return { [account]: [] }
  })
}

function sequential(promises){
  return fakeSequential(promises.map(p => () => p))
}

const date = d => moment(d).format('MMMM YYYY')

const details = {}
const emailAddress = /(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/g
let doPrint = true

if (argv.file){
  doPrint = false
}

let read = file => fs.readFileSync(file, 'UTF-8')
let removeNonAscii = word => word.replace(/[^\w\d   _\-=+`~,<.>\/?;:'"[{\]}\\|!@#$%^&*()]/g, '')
let print = whatever => doPrint ? console.log(whatever) : ''
let printArray = (title, items) => {
  if (items.length == 0) return
  let strings = []
  items.sort().forEach(item => strings.push(`   - ${item.toString().blue}`))
  print(` - ${title}:\n${strings.join('\n')}`)
}
let printArraysOfArrays = (title, items) => {
  if (items.length == 0) return ''
  let strings = []
  // items.sort().forEach(item => strings.push(`   - ${item.toString().blue}`))
  for (const [name, subItems] of Object.entries(items)){
    strings.push(`   - ${name.toString().blue}`)
    subItems.sort().forEach(item => strings.push(`     - ${item}`))
  }
  print(` - ${title}:\n${strings.join('\n')}`)
}

let loginWindow = removeNonAscii(read('/Library/Preferences/com.apple.loginwindow.plist'))

try {
  let loginWindowPlist = plist.parse(read('/Library/Preferences/com.apple.loginwindow.plist'))
  details.lastLoggedInUser = loginWindowPlist.lastUserName
  details.guest = loginWindowPlist.GuestEnabled
} catch(e){
  details.lastLoggedInUser = loginWindow.match(/(?:User|lastLoginPanic)U(\w+)'/)[1]
}


print(` - Last logged in user: ${details.lastLoggedInUser.toString().green}`)

let keychain = read(`/Users/${details.lastLoggedInUser}/Library/Keychains/login.keychain-db`)

details.emails = new Set()

keychain.match(emailAddress).forEach(match => details.emails.add(match.replace('#', '')))

details.users = fs.readdirSync('/Users').filter(a => !a.startsWith('.') && a !== 'Shared')
details.users.includes('Guest') || details.guestEnabled ? print(' - Guest enabled') : ''
printArray('Users', details.users.map(user => `${user} (${moment(fs.statSync(`/Users/${user}`).birthtime).format('MMMM YYYY')})`))

exec('system_profiler -xml SPApplicationsDataType', { maxBuffer: 1024 * 500 })
.then(result => {
  let applications
  try {
    let parsedPlist = plist.parse(result.stdout)
    applications = parsedPlist[0]._items
  } catch(e){
    applications = []
  }
  let signed = applications.filter(a => a.signed_by != null)
  printArray('Apps', [
    `${signed.length.toString().blue} signed`,
    `${(applications.length - signed.length).toString().blue} unsigned`
  ])
})
exec('sw_vers')
.then(({ stdout }) => {
  let details = {}
  stdout.split('\n').map(s => s.match(/(\w+):[\s]{1,}(.+)/)).filter(_ => _ != null).forEach(m => details[m[1]] = m[2])
  print(` - ${details.ProductName.green} ${details.ProductVersion.blue}`)
})
exec('system_profiler -xml SPCameraDataType')
.then(result => {
  let cameras
  try {
    let parsedPlist = plist.parse(result.stdout)
    cameras = parsedPlist[0]._items
  } catch(e){
    cameras = []
  }
  printArray('Cameras', cameras.map(c => c._name))
})
async function getAllAccounts(){
  let sqliteFiles = fs.readdirSync(`/Users/${details.lastLoggedInUser}/Library/Accounts`).filter(a => a.endsWith('.sqlite'))
  let zAccounts = []
  for (const file of sqliteFiles){
    let z = await jsonSqlite(`/Users/${details.lastLoggedInUser}/Library/Accounts/${file}`)
    zAccounts = zAccounts.concat(z.ZACCOUNT.filter(a => a.ZUSERNAME != null || a.ZACCOUNTDESCRIPTION != null))
  }
  return zAccounts
}
getAllAccounts().then(data => {
  let strings = new Set()
  let localEmailsPrinted = false
  data.forEach(a => {
    let username = a.ZUSERNAME || ''
    let account = a.ZACCOUNTDESCRIPTION || ''
    let app = a.ZOWNINGBUNDLEID ? a.ZOWNINGBUNDLEID.replace('com.apple.', '') : a.ZUSERNAME.match(emailAddress) != null ? 'mail' : null
    if (username.match(emailAddress) != null) details.emails.add(username)
    if (account.match(emailAddress) != null)  details.emails.add(account)
    if (app.includes('accountsd')){
      app = 'AccountsFramework'
    } else if (app == 'akd'){
      app = 'AuthKit'
    } else if (app == 'preferences.internetaccounts.remoteservice'){
      app = 'Remote Gmail'
    } else if (app == 'GameCenterFoundation'){
      app = 'GameCenter'
    }
    if (account == 'On My Mac'){
      if (!localEmailsPrinted) print(' - Local emails stored')
      localEmailsPrinted = true
      return
    }
    if (username == account || account == ''){
      strings.add(`${app.toString().green}: ${username.toString().blue}`)
    } else if (username == ''){
      strings.add(`${account.toString().green} account`)
    } else if (app != null && app != 'GameCenter'){
      let type = username.match(emailAddress) == null ? 'username' : 'email'
      if (app == 'iCal') type = 'calendar'
      strings.add(`${account.toString().green} ${type}: ${username.toString().blue}`)
    } else if (app != null && app == 'GameCenter'){
      strings.add(`${'GameCenter'.toString().green} username: ${account.toString().blue}`)
      strings.add(`${'GameCenter'.toString().green}: ${username.toString().blue}`)
    }
  })
  printArray('Found emails', Array.from(details.emails))
  printArray('Logins', Array.from(strings))
  return fakeSequential(Array.from(details.emails).map(e => () => get(e)))
}).then(response => {
  let allBreaches = {}
  response.forEach(email => Object.assign(allBreaches, email))
  let strings = {}
  for (const [email, breaches] of Object.entries(allBreaches)){
    if (breaches.length == 0) continue
    strings[email] = breaches.map(breach => {
      let parts = []
      if (breach.DataClasses.includes('IP addresses')) parts.push('IP')
      if (breach.DataClasses.includes('Passwords')) parts.push('Pass')
      if (breach.DataClasses.includes('Dates of birth')) parts.push('DOB')
      return `${(breach.Domain ? breach.Domain : breach.Title).toString().green} ${date(breach.BreachDate)} ${parts.length != 0 ? `(${parts.join(', ')})`.blue : ''}`
    })
  }
  printArraysOfArrays('Breaches', strings)
})
