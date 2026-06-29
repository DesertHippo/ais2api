const session = require("express-session");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const express = require("express");
const WebSocket = require("ws");
const http = require("http");
const { EventEmitter } = require("events");
const fs = require("fs");
const path = require("path");
const { firefox } = require("playwright");
const os = require("os");

// ===================================================================================
// AUTH SOURCE MANAGEMENT MODULE
// ===================================================================================
class AuthSource {
  constructor(logger) {
    this.logger = logger;
    this.authMode = "file";
    this.availableIndices = [];
    this.initialIndices = [];
    this.accountNameMap = new Map();

    if (process.env.AUTH_JSON_1) {
      this.authMode = "env";
      this.logger.info(
        "[Auth] 璉�瘚见� AUTH_JSON_1 ?臬??㗛?嚗�??Ｗ�?臬??㗛?霈方?璅∪???,
      );
    } else {
      this.logger.info(
        '[Auth] ?芣?瘚见�?臬??㗛?霈方?嚗�?雿輻鍂 "auth/" ?桀?銝讠??�辣??,
      );
    }

    this._discoverAvailableIndices(); // ?脲郊?𤑳緵?�?匧??函?皞?
    this._preValidateAndFilter(); // 憸�?撉�僎餈�誘?㗇聢撘誯?霂舐?皞?

    if (this.availableIndices.length === 0) {
      this.logger.error(
        `[Auth] ?游𦶢?躰秤嚗𡁜銁 '${this.authMode}' 璅∪?銝𧢲𧊋?曉�隞颱??㗇??�恕霂�??�,
      );
      throw new Error("No valid authentication sources found.");
    }
  }

  _discoverAvailableIndices() {
    let indices = [];
    if (this.authMode === "env") {
      const regex = /^AUTH_JSON_(\d+)$/;
      // [?喲睸靽桀?] 摰峕㟲??for...in 敺芰㴓嚗𣬚鍂鈭擧醌?𤩺??厩㴓憓�???
      for (const key in process.env) {
        const match = key.match(regex);
        if (match && match[1]) {
          indices.push(parseInt(match[1], 10));
        }
      }
    } else {
      // 'file' mode
      const authDir = path.join(__dirname, "auth");
      if (!fs.existsSync(authDir)) {
        this.logger.warn('[Auth] "auth/" ?桀?銝滚??具�?);
        this.availableIndices = [];
        return;
      }
      try {
        const files = fs.readdirSync(authDir);
        const authFiles = files.filter((file) => /^auth-\d+\.json$/.test(file));
        indices = authFiles.map((file) =>
          parseInt(file.match(/^auth-(\d+)\.json$/)[1], 10),
        );
      } catch (error) {
        this.logger.error(`[Auth] ?急? "auth/" ?桀?憭梯揖: ${error.message}`);
        this.availableIndices = [];
        return;
      }
    }

    // 摮睃??急??啁??笔?蝝Ｗ?
    this.initialIndices = [...new Set(indices)].sort((a, b) => a - b);
    this.availableIndices = [...this.initialIndices]; // ?�?霈暸�?舐鍂

    this.logger.info(
      `[Auth] ??'${this.authMode}' 璅∪?銝页??脲郊?𤑳緵 ${
        this.initialIndices.length
      } 銝芾恕霂�?: [${this.initialIndices.join(", ")}]`,
    );
  }

  _preValidateAndFilter() {
    if (this.availableIndices.length === 0) return;

    this.logger.info("[Auth] 撘�憪钅?璉�撉峕??㕑恕霂�??�SON?澆?...");
    const validIndices = [];
    const invalidSourceDescriptions = [];

    for (const index of this.availableIndices) {
      // 瘜冽?嚗朞??峕?隞祈??其?銝芸??函??�??𣇉? getAuthContent
      const authContent = this._getAuthContent(index);
      if (authContent) {
        try {
          const authData = JSON.parse(authContent);
          validIndices.push(index);
          this.accountNameMap.set(
            index,
            authData.accountName || "N/A (?芸𦶢??",
          );
        } catch (e) {
          invalidSourceDescriptions.push(`auth-${index}`);
        }
      } else {
        invalidSourceDescriptions.push(`auth-${index} (?䭾?霂餃?)`);
      }
    }

    if (invalidSourceDescriptions.length > 0) {
      this.logger.warn(
        `?𩤃? [Auth] 憸�?撉�???${
          invalidSourceDescriptions.length
        } 銝芣聢撘誯?霂舀??䭾?霂餃??�恕霂�?: [${invalidSourceDescriptions.join(
          ", ",
        )}]嚗�?隞𤾸虾?典?銵其葉蝘駁膄?�,
      );
    }

    this.availableIndices = validIndices;
  }

  // 銝�銝芸??刻??拙遆?堆?隞�鍂鈭𡡞?璉�撉䕘??踹??亙?瘙⊥?
  _getAuthContent(index) {
    if (this.authMode === "env") {
      return process.env[`AUTH_JSON_${index}`];
    } else {
      const authFilePath = path.join(__dirname, "auth", `auth-${index}.json`);
      if (!fs.existsSync(authFilePath)) return null;
      try {
        return fs.readFileSync(authFilePath, "utf-8");
      } catch (e) {
        return null;
      }
    }
  }

  getAuth(index) {
    if (!this.availableIndices.includes(index)) {
      this.logger.error(`[Auth] 霂瑟?鈭�??�?銝滚??函?霈方?蝝Ｗ?: ${index}`);
      return null;
    }

    let jsonString = this._getAuthContent(index);
    if (!jsonString) {
      this.logger.error(`[Auth] ?刻粉?𡝗𧒄?䭾??瑕?霈方?皞?#${index} ?�?摰嫘��);
      return null;
    }

    try {
      return JSON.parse(jsonString);
    } catch (e) {
      this.logger.error(
        `[Auth] 閫???亥䌊霈方?皞?#${index} ?�SON?�捆憭梯揖: ${e.message}`,
      );
      return null;
    }
  }
}
// ===================================================================================
// BROWSER MANAGEMENT MODULE
// ===================================================================================

class BrowserManager {
  constructor(logger, config, authSource) {
    this.logger = logger;
    this.config = config;
    this.authSource = authSource;
    this.browser = null;
    this.context = null;
    this.page = null;
    this.currentAuthIndex = 0;
    this.scriptFileName = "black-browser.js";
    
    this.noButtonCount = 0;
    this.isWakeupRunning = false;
    this.uiLock = Promise.resolve();
    this.uiWaitQueueCount = 0;

    this.launchArgs = [
      "--disable-dev-shm-usage", // ?喲睸嚗�俈甇?/dev/shm 蝛粹𡢿銝滩雲撖潸稲瘚讛??典援皞?
      "--disable-gpu",
      "--no-sandbox", // ?典??鞟?摰孵膥?臬?銝剝�𡁜虜?�閬?
      "--disable-setuid-sandbox",
      "--disable-infobars",
      "--disable-background-networking",
      "--disable-default-apps",
      "--disable-extensions",
      "--disable-sync",
      "--disable-translate",
      "--metrics-recording-only",
      "--mute-audio",
      "--safebrowsing-disable-auto-update",
      "--disable-background-timer-throttling",
      "--disable-backgrounding-occluded-windows",
      "--disable-renderer-backgrounding",
    ];

    if (this.config.browserExecutablePath) {
      this.browserExecutablePath = this.config.browserExecutablePath;
    } else {
      const platform = os.platform();
      if (platform === "linux") {
        this.browserExecutablePath = path.join(
          __dirname,
          "camoufox-linux",
          "camoufox",
        );
      } else {
        throw new Error(`Unsupported operating system: ${platform}`);
      }
    }
  }

  notifyUserActivity() {
    if (this.noButtonCount > 0) {
      this.logger.info(
        "[Browser] ???嗅�?冽�霂瑟?靽∪噡嚗�撩?嗅𤧅?鍦??唳?瘚?(?滨蔭霈⊥㺭??",
      );
      this.noButtonCount = 0;
    }
  }

  async launchOrSwitchContext(authIndex) {
    if (this.context) {
      this.logger.info("[Browser] 甇?銁?喲𡡒?抒?瘚讛??其?銝𧢲?...");
      try {
        try { await this.context.close(); } catch (e) { this.logger.warn('[Browser] ?喲𡡒?找?銝𧢲??嗅??罸?霂? ' + e.message); try { if (this.browser) await this.browser.close(); } catch (be) {} this.browser = null; }
      } catch (e) {
        this.logger.warn("[Browser] ?喲𡡒?找?銝𧢲??嗅??罸?霂?(?航�撌脣援皞?: " + e.message);
        try {
            if (this.browser) await this.browser.close();
        } catch (be) {}
        this.browser = null;
      }
      this.context = null;
      this.page = null;
      this.logger.info("[Browser] ?找?銝𧢲?撌脫??��?);
    }

    if (!this.browser) {
      this.logger.info("?? [Browser] 瘚讛??典?靘𧢲𧊋餈鞱?嚗峕迤?刻?銵屸?甈∪鍳??..");
      if (!fs.existsSync(this.browserExecutablePath)) {
        throw new Error(
          `Browser executable not found at path: ${this.browserExecutablePath}`,
        );
      }
      this.browser = await firefox.launch({
        headless: true,
        executablePath: this.browserExecutablePath,
        args: this.launchArgs,
      });
      this.browser.on("disconnected", () => {
        this.logger.error("??[Browser] 瘚讛??冽?憭𡝗鱏撘�餈墧𦻖嚗?);
        this.browser = null;
        this.context = null;
        this.page = null;
      });
      this.logger.info("??[Browser] 瘚讛??典?靘见歇?𣂼??臬𢆡??);
    }
    const sourceDescription =
      this.authSource.authMode === "env"
        ? `?臬??㗛? AUTH_JSON_${authIndex}`
        : `?�辣 auth-${authIndex}.json`;
    this.logger.info("==================================================");
    this.logger.info(
      `?? [Browser] 甇?銁銝箄揭??#${authIndex} ?𥕦遣?啁?瘚讛??其?銝𧢲?`,
    );
    this.logger.info(`   ??霈方?皞? ${sourceDescription}`);
    this.logger.info("==================================================");

    const storageStateObject = this.authSource.getAuth(authIndex);
    if (!storageStateObject) {
      throw new Error(
        `Failed to get or parse auth source for index ${authIndex}.`,
      );
    }
    const buildScriptContent = fs.readFileSync(
      path.join(__dirname, this.scriptFileName),
      "utf-8",
    );

    try {
      this.context = await this.browser.newContext({
        storageState: storageStateObject,
        viewport: null,
      });
      this.page = await this.context.newPage();
      this.page.on("console", (msg) => {
        const msgText = msg.text();
        if (msgText.includes("Content-Security-Policy: (Report-Only policy)")) {
          return;
        }
        if (msgText.includes("[ProxyClient]")) {
          this.logger.info(
            `[Browser] ${msgText.replace("[ProxyClient] ", "")}`,
          );
        } else if (msg.type() === "error") {
          this.logger.error(`[Browser Page Error] ${msgText}`);
        }
      });

      // 憓𧼮? 1嚗𡁶??祇△?Ｗ援皞?
      this.page.on("crash", () => {
        this.logger.error(
          `?辶 [Browser] ?游𦶢嚗𡁻△?Ｚ?蝔见援皞?(Crash)嚗�??滩揭?瑞揣撘? ${authIndex}`,
        );
      });

      // 憓𧼮? 2嚗𡁶??祆?憭𣇉?憿菟𢒰頝唾蓮?硋�??
      this.page.on("framenavigated", (frame) => {
        // ?芸�瘜其蜓獢�沲?�歲頧?
        if (this.page && frame === this.page.mainFrame()) {
          const newUrl = frame.url();
          if (
            newUrl !== "about:blank" &&
            !newUrl.includes(this.config.targetUrl)
          ) {
            this.logger.warn(`?𩤃? [Browser] ?�𢒰?潛?鈭�歲頧??齿鰵?渡?嚗�鰵 URL: ${newUrl}`);
          }
        }
      });

      // 憓𧼮? 3嚗𡁶???WebSocket 蝥批�?�?霂?(?嫣噶撖寧�)
      this.page.on("websocket", (ws) => {
        ws.on("close", () =>
          this.logger.info(
            `[Browser Network] 憿菟𢒰?�? WebSocket 餈墧𦻖撌脣�?? ${ws.url()}`,
          ),
        );
        ws.on("error", (err) =>
          this.logger.error(
            `[Browser Network] 憿菟𢒰?�? WebSocket ?𤑳??躰秤: ${err}`,
          ),
        );
      });

      this.logger.info(`[Browser] 甇?銁撖潸⏛?喟𤌍?�?憿?..`);
      const targetUrl = this.config.targetUrl;
      await this.page.goto(targetUrl, {
        timeout: 180000,
        waitUntil: "domcontentloaded",
      });
      this.logger.info("[Browser] 憿菟𢒰?㰘蝸摰峕???);

      await this.page.waitForTimeout(3000);

      const currentUrl = this.page.url();
      let pageTitle = "";
      try {
        pageTitle = await this.page.title();
      } catch (e) {
        this.logger.warn(`[Browser] ?䭾??瑕?憿菟𢒰?�?: ${e.message}`);
      }

      this.logger.info(`[Browser] [霂𦠜鱏] URL: ${currentUrl}`);
      this.logger.info(`[Browser] [霂𦠜鱏] Title: "${pageTitle}"`);

      // 1. 璉�??Cookie ?臬炏憭望? (頝唾蓮?䂿蒈敶閖△)
      if (
        currentUrl.includes("accounts.google.com") ||
        currentUrl.includes("ServiceLogin") ||
        pageTitle.includes("Sign in") ||
        pageTitle.includes("?餃?")
      ) {
        throw new Error(
          "?辶 Cookie 撌脣仃??餈�?嚗�?閫�膥鋡恍?摰𡁜??唬? Google ?餃?憿菟𢒰?�窈?齿鰵?𣂼? storageState??,
        );
      }

      // 2. 璉�??IP ?啣躹?𣂼� (Region Unsupported)
      // ?𡁜虜?�???"Google AI Studio is not available in your location"
      if (
        pageTitle.includes("Available regions") ||
        pageTitle.includes("not available")
      ) {
        throw new Error(
          "?辶 敶枏? IP 銝齿𣈲?�挪??Google AI Studio?�窈?湔揢?��?𡡞??荔?",
        );
      }

      // 3. 璉�??IP 憌擧綉 (403 Forbidden)
      if (pageTitle.includes("403") || pageTitle.includes("Forbidden")) {
        throw new Error(
          "?辶 403 Forbidden嚗𡁜???IP 靽∟?餈�?嚗諹◤ Google 憌擧綉?垍?霈輸䔮??,
        );
      }

      // 4. 璉�?亦蒾撅?(蝵𤑳??�榆?硋?頧賢仃韐?
      if (currentUrl === "about:blank") {
        throw new Error(
          "?辶 憿菟𢒰?㰘蝸憭梯揖 (about:blank)嚗�虾?賣糓蝵𤑳?餈墧𦻖頞�𧒄?𡝗?閫�膥撏拇???,
        );
      }

      this.logger.info(
        `[Browser] 餈𥕦� 20蝘?璉�?交?蝔?(?格?: Cookie + Got it + ?唳?撘訫紡)...`,
      );

      const startTime = Date.now();
      const timeLimit = 20000;

      // ?嗆��扇敶閗”
      const popupStatus = {
        cookie: false,
        gotIt: false,
        guide: false,
        continueBtn: false,
      };

      while (Date.now() - startTime < timeLimit) {
        // 憒�?3銝芷�憭�?餈�?嚗𣬚??駁��??---
        if (popupStatus.cookie && popupStatus.gotIt && popupStatus.guide) {
          this.logger.info(
            `[Browser] ??摰𣬚?嚗?銝芸撕蝒堒�?典??�?瘥𤏪??𣂼?餈𥕦�銝衤?甇乓��,
          );
          break;
        }

        let clickedInThisLoop = false;

        // 1. 璉�??Cookie "Agree" (憒�?餈䀹瓷?寡?)
        if (!popupStatus.cookie) {
          try {
            const agreeBtn = this.page.locator('button:text("Agree")').first();
            if (await agreeBtn.isVisible({ timeout: 100 })) {
              await agreeBtn.click({ force: true });
              this.logger.info(`[Browser] ??(1/3) ?孵稬鈭?"Cookie Agree"`);
              popupStatus.cookie = true;
              clickedInThisLoop = true;
            }
          } catch (e) {}
        }

        // 2. 璉�??"Got it" (憒�?餈䀹瓷?寡?)
        if (!popupStatus.gotIt) {
          try {
            const gotItBtn = this.page
              .locator('div.dialog button:text("Got it")')
              .first();
            if (await gotItBtn.isVisible({ timeout: 100 })) {
              await gotItBtn.click({ force: true });
              this.logger.info(`[Browser] ??(2/3) ?孵稬鈭?"Got it" 撘寧?`);
              popupStatus.gotIt = true;
              clickedInThisLoop = true;
            }
          } catch (e) {}
        }

        // 3. 璉�???唳?撘訫紡 "Close" (憒�?餈䀹瓷?寡?)
        if (!popupStatus.guide) {
          try {
            const closeBtn = this.page
              .locator('button[aria-label="Close"]')
              .first();
            if (await closeBtn.isVisible({ timeout: 100 })) {
              await closeBtn.click({ force: true });
              this.logger.info(`[Browser] ??(3/3) ?孵稬鈭?"?唳?撘訫紡?喲𡡒" ?厰僼`);
              popupStatus.guide = true;
              clickedInThisLoop = true;
            }
          } catch (e) {}
        }

        if (!popupStatus.continueBtn) {
          try {
            const clicked = await this.page.evaluate(() => {
              const btns = Array.from(document.querySelectorAll("button"));
              const target = btns.find(
                (b) =>
                  b.innerText && b.innerText.includes("Continue to the app"),
              );
              if (target) {
                target.click();
                return true;
              }
              return false;
            });

            if (clicked) {
              this.logger.info(
                `[Browser] ??(4/4) ?毺?JS?𣂼??孵稬 "Continue to the app"`,
              );
              popupStatus.continueBtn = true;
              clickedInThisLoop = true;
              this.logger.info(
                `[Browser] ??撌脩＆霈方??亙??剁??𣂼?蝏�迫撘寧?蝑匧?敺芰㴓?�,
              );
              break;
            }
          } catch (e) {}
        }
        try {
          const isAppRunning = await this.page.evaluate(() => {
            // ?芾?憿菟𢒰?�枂?唬? ProxyClient ?�??綽?撠梯秩?𦒘誨?�歇蝏讛?韏瑟䔉鈭?
            return document.body.innerText.includes("[ProxyClient]");
          });
          if (isAppRunning) {
            this.logger.info(
              `[Browser] ??璉�瘚见�?��?臬?撌脣停蝏迎?頝喳枂撘寧?蝑匧??�,
            );
            break;
          }
        } catch (e) {}

        // 憒�??祈蔭?孵稬鈭�??殷?蝔滚凝蝑劐?銝见𢆡?鳴?憒�?瘝∠�嚗𣬚?敺?蝘㘾�?齿香敺芰㴓蝛箄蓮
        await this.page.waitForTimeout(clickedInThisLoop ? 500 : 1000);
      }

      this.logger.info(
        `[Browser] 撘寧?璉�?亦???(?埈𧒄: ${Math.round(
          (Date.now() - startTime) / 1000,
        )}s)嚗𣬚??? ` +
          `Cookie[${popupStatus.cookie ? "Ok" : "No"}], ` +
          `GotIt[${popupStatus.gotIt ? "Ok" : "No"}], ` +
          `Guide[${popupStatus.guide ? "Ok" : "No"}]`,
      );

      this.currentAuthIndex = authIndex;
      this._startBackgroundWakeup();
      this.logger.info("[Browser] (?𤾸蝱隞餃𦛚) ?椘儭??烐綉餈𤤿?撌脣鍳??..");
      await this.page.waitForTimeout(1000);
      this.logger.info(
        "[Browser] ??甇?銁?煾��蜓?典𤧅?坿窈瘙�誑閫血? Launch 瘚�?...",
      );
      try {
        await this.page.evaluate(async () => {
          try {
            await fetch(
              "https://generativelanguage.googleapis.com/v1beta/models?key=ActiveTrigger",
              {
                method: "GET",
                headers: { "Content-Type": "application/json" },
              },
            );
          } catch (e) {
            console.log(
              "[ProxyClient] 銝餃𢆡?日?霂瑟?撌脣???(憸�??�虾?賭?憭梯揖嚗諹?敺�迤撣?",
            );
          }
        });
        this.logger.info("[Browser] ??銝餃𢆡?日?霂瑟?撌脣??��?);
      } catch (e) {
        this.logger.warn(
          `[Browser] 銝餃𢆡?日?霂瑟??煾��?撣?(銝滚蔣?滢蜓瘚�?): ${e.message}`,
        );
      }

      this.logger.info("==================================================");
      this.logger.info(`??[Browser] 韐血噡 ${authIndex} ?�?銝𧢲??嘥??𡝗??�?`);
      this.logger.info("??[Browser] 瘚讛??典恥?瑞垢撌脣?憭�停蝏芥�?);
      this.logger.info("==================================================");
    } catch (error) {
      this.logger.error(
        `??[Browser] 韐行� ${authIndex} ?�?銝𧢲??嘥??硋仃韐? ${error.message}`,
      );
      if (this.browser) {
        await this.browser.close();
        this.browser = null;
      }
      throw error;
    }
  }

  async closeBrowser() {
    if (this.browser) {
      this.logger.info("[Browser] 甇?銁?喲𡡒?港葵瘚讛??典?靘?..");
      await this.browser.close();
      this.browser = null;
      this.context = null;
      this.page = null;
      this.logger.info("[Browser] 瘚讛??典?靘见歇?喲𡡒??);
    }
  }

  async switchAccount(newAuthIndex) {
    this.logger.info(
      `?? [Browser] 撘�憪贝揭?瑕??? 隞?${this.currentAuthIndex} ??${newAuthIndex}`,
    );
    await this.launchOrSwitchContext(newAuthIndex);
    this.logger.info(
      `??[Browser] 韐血噡?�揢摰峕?嚗�??滩揭?? ${this.currentAuthIndex}`,
    );
  }

  async _startBackgroundWakeup() {
    if (this.isWakeupRunning) {
      this.logger.warn(
        "[Browser] (?𤾸蝱隞餃𦛚) 靽脲暑?烐綉撌脣銁餈鞱?嚗�蕭?仿?憭滚鍳?刻窈瘙��?,
      );
      return;
    }
    this.isWakeupRunning = true;

    const currentPage = this.page;
    await new Promise((r) => setTimeout(r, 1500));

    if (!currentPage || currentPage.isClosed() || this.page !== currentPage) {
      this.isWakeupRunning = false;
      return;
    }

    this.logger.info("[Browser] (?𤾸蝱隞餃𦛚) ?椘儭?蝵煾△靽脲暑?烐綉撌脣鍳??);

    while (
      currentPage &&
      !currentPage.isClosed() &&
      this.page === currentPage
    ) {
      try {
        // --- [憓𧼮撩甇仿炊 1] 撘箏�?日?憿菟𢒰 (閫?�銝滚?霂瑟?銝滚�?啁??桅?) ---
        await currentPage.bringToFront().catch(() => {});

        // ?喲睸嚗𡁜銁?惩仍璅∪?銝页?隞�? bringToFront ?航�銝滚?嚗屸?閬�憚?𣳇??�宏?冽䔉閫血?皜脫?撣?
        // ?𤩺㦤?其?銝芣?摰喳躹?蠘蝠敺格??券???
        await currentPage.mouse.move(10, 10);
        await currentPage.mouse.move(20, 20);

        // --- [憓𧼮撩甇仿炊 2] ?箄�?交𪄳 (?交𪄳?�𧋦撟嗅?銝𢠃?摰𡁜虾鈭支??嗥漣) ---
        const targetInfo = await currentPage.evaluate(() => {
          // 1. ?湔𦻖CSS摰帋?
          try {
            const preciseCandidates = Array.from(
              document.querySelectorAll(
                ".interaction-modal p, .interaction-modal button",
              ),
            );
            for (const el of preciseCandidates) {
              const text = (el.innerText || "").trim();
              if (/Launch|rocket_launch/i.test(text)) {
                const rect = el.getBoundingClientRect();
                if (rect.width > 0 && rect.height > 0) {
                  return {
                    found: true,
                    x: rect.left + rect.width / 2,
                    y: rect.top + rect.height / 2,
                    tagName: el.tagName,
                    text: text.substring(0, 15),
                    strategy: "precise_css", // ?�扇嚗朞??舫�朞?蝎曉?CSS?曉�??
                  };
                }
              }
            }
          } catch (e) {}
          // 2. ?急?Y頧?00-800?�凒?餅??�?
          const MIN_Y = 400;
          const MAX_Y = 800;

          // 颲�𨭌?賣㺭嚗𡁜ế?剖?蝝䭾糓?血虾閫�??典躹?笔?
          const isValid = (rect) => {
            return (
              rect.width > 0 &&
              rect.height > 0 &&
              rect.top > MIN_Y &&
              rect.top < MAX_Y
            );
          };

          // ?急??�?匧??怠�?株??�?蝝?
          const candidates = Array.from(
            document.querySelectorAll("button, span, div, a, i"),
          );

          for (const el of candidates) {
            const text = (el.innerText || "").trim();
            // ?寥? Launch ??rocket_launch ?暹???
            if (!/Launch|rocket_launch/i.test(text)) continue;

            let targetEl = el;
            let rect = targetEl.getBoundingClientRect();

            // [?喲睸隡睃?] 憒�?敶枏??�?敺�??𡝗糓蝥舀??砍捆?剁?撠肽??睲???3 撅��蝥?
            let parentDepth = 0;
            while (parentDepth < 3 && targetEl.parentElement) {
              if (
                targetEl.tagName === "BUTTON" ||
                targetEl.getAttribute("role") === "button"
              ) {
                break;
              }
              const parent = targetEl.parentElement;
              const pRect = parent.getBoundingClientRect();
              if (isValid(pRect)) {
                targetEl = parent;
                rect = pRect;
              }
              parentDepth++;
            }

            // ?�蝏�???
            if (isValid(rect)) {
              return {
                found: true,
                x: rect.left + rect.width / 2,
                y: rect.top + rect.height / 2,
                tagName: targetEl.tagName,
                text: text.substring(0, 15),
                strategy: "fuzzy_scan", // ?�扇嚗朞??舫�朞?璅∠??急??曉�??
              };
            }
          }
          return { found: false };
        });

        // --- [憓𧼮撩甇仿炊 3] ?扯??滢? ---
        if (targetInfo.found) {
          this.noButtonCount = 0;
          this.logger.info(
            `[Browser] ?㴓 ?�??格? [${targetInfo.tagName}] (蝑𣇉裦: ${
              targetInfo.strategy === "precise_css" ? "蝎曉?摰帋?" : "璅∠??急?"
            })...`,
          );

          // === 蝑𣇉裦 A: ?拍??孵稬 (璅⊥??笔?曌䭾?) ===
          // 1. 蝘餃𢆡餈�縧
          await currentPage.mouse.move(targetInfo.x, targetInfo.y, {
            steps: 5,
          });
          // 2. ?砍? (蝏?hover ?瑕?銝�?孵?摨娍𧒄??
          await new Promise((r) => setTimeout(r, 300));
          // 3. ?劐?
          await currentPage.mouse.down();
          // 4. ?踵? (?𣂷??厰僼?脰秤閫佗??�閬�?雿譍?撠譍???
          await new Promise((r) => setTimeout(r, 400));
          // 5. ?祈絲
          await currentPage.mouse.up();

          this.logger.info(`[Browser] ?鰐儭??拍??孵稬撌脫�銵䕘?撉諹?蝏𤘪?...`);
          // 蝑匧? 1.5 蝘垍??�?
          await new Promise((r) => setTimeout(r, 1500));

          // === 蝑𣇉裦 B: JS 銵亙? (憒�??拍??孵稬憭梯揖) ===
          // ?齿活璉�?交??格糓?西??典???
          const isStillThere = await currentPage.evaluate(() => {
            // ?餉??䔶?嚗𣬚??閙???
            const allText = document.body.innerText;
            // 蝞�?閧??湔??仿△?Ｗ虾閫�躹?臬炏餈䀹???葵?孵?雿滨蔭?�?摮?
            // 餈䠷?銝箔??扯�?𡁶??吔??齿活?急??�?
            const els = Array.from(
              document.querySelectorAll('button, span, div[role="button"]'),
            );
            return els.some((el) => {
              const r = el.getBoundingClientRect();
              return (
                /Launch|rocket_launch/i.test(el.innerText) &&
                r.top > 400 &&
                r.top < 800 &&
                r.height > 0
              );
            });
          });

          if (isStillThere) {
            this.logger.warn(
              `[Browser] ?𩤃? ?拍??孵稬隡潔??䭾?嚗�??桐??剁?嚗�?霂?JS 撘箏??孵稬...`,
            );

            // ?湔𦻖?冽?閫�膥?��閫血? click 鈭衤辣
            await currentPage.evaluate(() => {
              const MIN_Y = 400;
              const MAX_Y = 800;
              const candidates = Array.from(
                document.querySelectorAll('button, span, div[role="button"]'),
              );
              for (const el of candidates) {
                const r = el.getBoundingClientRect();
                if (
                  /Launch|rocket_launch/i.test(el.innerText) &&
                  r.top > MIN_Y &&
                  r.top < MAX_Y
                ) {
                  // 撠肽??曉�?�餈𤑳? button ?嗥漣?孵稬
                  let target = el;
                  if (target.closest("button"))
                    target = target.closest("button");
                  target.click(); // ?毺? JS ?孵稬
                  console.log(
                    "[ProxyClient] JS Click triggered on " + target.tagName,
                  );
                  return true;
                }
              }
            });
            await new Promise((r) => setTimeout(r, 2000));
          } else {
            this.logger.info(`[Browser] ???拍??孵稬?𣂼?嚗峕??桀歇瘨�仃?�);
            await new Promise((r) => setTimeout(r, 60000));
            this.noButtonCount = 21;
          }
        } else {
          this.noButtonCount++;
          // 5. [?喲睸] ?箄�隡𤑳??餉? (?舀?鋡怠𤧅??
          if (this.noButtonCount > 20) {
            for (let i = 0; i < 30; i++) {
              if (this.noButtonCount === 0) {
                break;
              }
              await new Promise((r) => setTimeout(r, 1000));
            }
          } else {
            await new Promise((r) => setTimeout(r, 1500));
          }
        }
      } catch (e) {
        await new Promise((r) => setTimeout(r, 1000));
      }
    }
    this.isWakeupRunning = false;
  }

  _acquireUiLock(signal) {
    let unlockNext;
    const nextLock = new Promise((resolve) => (unlockNext = resolve));
    const acquire = this.uiLock.then(() => {
      if (signal && signal.aborted) {
        unlockNext();
        throw new Error("CLIENT_DISCONNECTED: The client closed the connection before the lock could be acquired.");
      }
      return unlockNext;
    });
    this.uiLock = nextLock;
    return acquire;
  }

  async generateTextViaUI(promptText, modelName, systemInstructions = "", maxWaitMs = 300000, signal = null) {
    this.uiWaitQueueCount++;
    if (this.uiWaitQueueCount > 1) {
      this.logger.info(`[UI Auto] ?笔???�???????.. (????? ${this.uiWaitQueueCount - 1})`);
    }
    
    let unlock;
    try {
      unlock = await this._acquireUiLock(signal);
      if (signal && signal.aborted) throw new Error("CLIENT_DISCONNECTED");
      return await this._generateTextViaUIInternal(promptText, modelName, systemInstructions, maxWaitMs);
    } finally {
      this.uiWaitQueueCount--;
      if (typeof unlock === 'function') unlock();
    }
  }

  async _generateTextViaUIInternal(promptText, modelName, systemInstructions = "", maxWaitMs = 300000, retryCount = 0) {
    this.logger.info("[UI Auto] ?见??脰? UI ?芸??𤥁??�?瘙?..");
    
    try {
      if (!this.page || this.page.isClosed()) {
        this.logger.warn("[Browser] No browser page available or page is closed, attempting to recover browser...");
        try {
          const targetIndex = this.currentAuthIndex || (this.authSource && this.authSource.availableIndices && this.authSource.availableIndices[0]) || 1;
          await this.launchOrSwitchContext(targetIndex);
        } catch (err) {
          throw new Error("No browser page available and recovery failed: " + err.message);
        }
        if (!this.page || this.page.isClosed()) {
          throw new Error("No browser page available even after recovery attempt.");
        }
      }

      this.logger.info("[UI Auto] 甇?銁?齿鰵?渡?銝血??芾秐?冽鰵撠滩店?啣?...");
      // 撘瑕�瘥𤩺活?賡??唳㟲?�雯?�?蝣箔? React ?嗆��??其嗾瘛剁??踹??瑟??𥡝?撠舘稲?折�?航炊??DOM ?⊥香
      await this.page.goto('https://aistudio.google.com/prompts/new_chat', { waitUntil: 'domcontentloaded' });
      await this.page.waitForSelector('textarea[aria-label="Enter a prompt"]', { timeout: 15000 }).catch(() => {});
      
      // Handle System Instructions Native UI Box
      if (systemInstructions) {
        try {
          this.logger.info("[UI Auto] ?菜葫??System Instructions嚗�?閰西撓?亥秐?毺?閮剖?獢?..");
          const sysCard = await this.page.$('.system-instructions-card');
          if (sysCard) {
              await sysCard.click();
              await this.page.waitForTimeout(500); // Wait for sliding panel to open
              
              // The textarea inside the system instructions panel has formcontrolname="systemInstructions" or similar
              // We can find all textareas and pick the one that is NOT the main promptText box
              await this.page.evaluate((sysText) => {
                  const tas = Array.from(document.querySelectorAll('textarea'));
                  const sysTa = tas.find(t => t.getAttribute('aria-label') !== 'Enter a prompt');
                  if (sysTa) {
                      sysTa.focus();
                      document.execCommand('insertText', false, sysText);
                  }
              }, systemInstructions);
              await this.page.waitForTimeout(500);
          }
        } catch (err) {
            this.logger.warn("[UI Auto] 頛詨� System Instructions 憭望?: " + err.message);
        }
      }

      if (modelName) {
        this.logger.info(`[UI Auto] ?�?璅∪?: ${modelName}...`);
        try {
          const currentModel = await this.page.evaluate(() => {
            const el = document.querySelector("button.model-selector-card span[data-test-id=\"model-name\"]");
            return el ? el.innerText.trim() : "";
          });
          
          if (!currentModel.includes(modelName)) {
            await this.page.evaluate(() => document.querySelector("button.model-selector-card")?.click());
            await this.page.waitForTimeout(1000);
            
            // DUMP DOM state for analysis
            const btnIds = await this.page.evaluate(() => {
              const buttons = Array.from(document.querySelectorAll("button"));
              return buttons.map(b => b.id + " | " + b.className + " | " + b.innerText.replace(/\n/g, " ")).filter(t => t.includes("gemini") || t.includes("3.5")).join("\n");
            });
            this.logger.info(`[UI Auto] DEBUG BUTTONS:\n${btnIds}`);
            
            let targetId = modelName;
            
            const clicked = await this.page.evaluate((target) => {
              // 1. EXACT match first
              let btn = document.querySelector(`button[id="${target}"]`);
              if (btn) { btn.click(); return true; }
              
              // 2. Strict exact prefix match
              btn = document.querySelector(`button[id="model-carousel-row-models/${target}"]`) || document.querySelector(`button[id="models/${target}"]`);
              if (btn) { btn.click(); return true; }
              
              // 3. Precise Span check (Not includes, but exact match of the clean target to prevent flash-lite matching flash)
              const spans = Array.from(document.querySelectorAll("button span[data-test-id='model-name']"));
              const cleanTarget = target.replace("models/", "").replace("gemini-", "").replace(/-/g, " ").toLowerCase();
              for (const span of spans) {
                 const spanText = span.innerText.toLowerCase().replace(/-/g, " ");
                 // Precise matching: if target is "3.5 flash", don't match "3.5 flash lite"
                 if (spanText.includes(cleanTarget) && !spanText.includes("lite") && !spanText.includes("image")) {
                    span.closest("button").click();
                    return true;
                 }
              }
              return false;
            }, targetId);
            
            if (clicked) {
              this.logger.info(`[UI Auto] ?�?璅∪??𣂼?: ${modelName}`);
              await this.page.waitForTimeout(300);
            } else {
              this.logger.warn(`[UI Auto] Warning: ${modelName} not found`);
              await this.page.evaluate(() => document.querySelector("button.model-selector-card")?.click());
            }
          } else {
            this.logger.info(`[UI Auto] ?嗅?璅∪??? ${currentModel}`);
          }
        } catch (e) {
          this.logger.warn(`[UI Auto] ?�?璅∪?憭望?: ${e.message}`);
        }
      }
      this.logger.info("[UI Auto] 頛詨�?鞟內閰?..");
      
      // 摰匧�瑼Ｘ䰻嚗𡁶Ⅱ隤滩撓?交??臬炏摮睃銁
      const isTextareaPresent = await this.page.evaluate(() => !!document.querySelector('textarea[aria-label="Enter a prompt"]'));
      if (!isTextareaPresent) {
          const currentUrl = this.page.url();
          this.logger.warn(`[UI Auto] 頛詨�獢�?摮睃銁嚗�虾?質◤敶�枂閬𣇉??格??𤥁◤?餃枂?�𤌍?滨雯?�: ${currentUrl}`);
          // ?𡑒岫撘瑕�?𣈯??航�?�僕?曇?蝒?          await this.page.evaluate(() => {
              document.querySelectorAll('button').forEach(b => {
                  if (b.innerText.match(/got it|dismiss|close|ok|agree|accept/i)) b.click();
              });
          });
          await this.page.waitForTimeout(1000);
          
          if (currentUrl.includes('signin') || currentUrl.includes('ServiceLogin')) {
              throw new Error("AUTH_EXPIRED: 撣唾?撌脩蒈?綽??�閬�凒?啁蒈?亦???);
          }
          
          throw new Error("FAILED_TO_START: ?⊥??曉�撠滩店頛詨�獢�??�𢒰?航�?㰘?憭望?");
      }

      await this.page.fill('textarea[aria-label="Enter a prompt"]', promptText, { timeout: 10000 });
      await this.page.waitForTimeout(100);
      await this.page.focus('textarea[aria-label="Enter a prompt"]', { timeout: 5000 });
      await this.page.keyboard.press('Control+Enter');
      
      // Fallback: 蝣箔??毺??㗇?銝见縧嚗�???Control+Enter 鋡?React 敹賜裦嚗𣬚凒?交𪄳?厰?暺墧?
      await this.page.evaluate(() => {
         const runBtns = Array.from(document.querySelectorAll('button')).filter(b => b.innerText && b.innerText.includes('Run'));
         for (const b of runBtns) {
             if (!b.disabled) b.click();
         }
         const iconBtn = document.querySelector('button[aria-label*="Run"]');
         if (iconBtn && !iconBtn.disabled) iconBtn.click();
      });
      
      this.logger.info(`[UI Auto] ?鞟內閰𧼮歇?澆枂嚗𣬚?敺?AI ?�??噼? (?�憭𡁶?敺?${maxWaitMs/1000} 蝘?...`);
      
      let response = await this.page.evaluate(async ({timeout, targetModelName}) => {
        return new Promise((resolve) => {
          function extractText(node) {
              if (node.nodeType === 3) return node.textContent; // Text node
              if (node.nodeName === 'BR') return '\n';
              let text = '';
              for (let child of node.childNodes) {
                  text += extractText(child);
              }
              if (node.nodeName === 'P' || node.nodeName === 'DIV' || node.nodeName === 'LI') {
                  text += '\n';
              }
              return text;
          }
          
          let lastLength = 0;
          let unchangedCount = 0;
          let startTime = Date.now();
          let lastRetryTime = startTime;
          
          const check = setInterval(() => {
            let isProhibited = false;
            let isQuota = false;
            let isInternal = false;
            let isGenericError = false;

            // Safe UI Label Detection (Prevents false positives from long stories or user prompts)
            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
            let node;
            while ((node = walker.nextNode())) {
                if (node.parentElement && (node.parentElement.tagName === 'TEXTAREA' || node.parentElement.tagName === 'INPUT' || node.parentElement.closest('textarea'))) continue;
                const text = node.textContent.trim().toLowerCase();
                if (text.length === 0) continue;
                
                if (text.length < 50 && (text.includes('prohibited content') || text.includes('blocked for safety') || text.includes('safety setting'))) {
                    isProhibited = true;
                }
                if (text.length < 150 && (text.includes('paid api key') || text.includes("you've reached your quota") || text.includes("setup billing"))) {
                    isQuota = true;
                }
                if (text.length < 100 && (text.includes('an internal error has occurred') || text === 'internal error')) {
                    isInternal = true;
                }
                if (text.length < 50 && text.match(/something went wrong|network error|failed to fetch|unable to connect|server error/i)) {
                    isGenericError = true;
                }
            }

            if (isProhibited) {
              clearInterval(check);
              resolve("__UI_AUTO_PROHIBITED_CONTENT__");
              return;
            }
            if (isQuota) {
              clearInterval(check);
              resolve("__UI_AUTO_QUOTA_EXCEEDED__");
              return;
            }
            if (isInternal) {
              clearInterval(check);
              resolve("__UI_AUTO_INTERNAL_ERROR__");
              return;
            }
            if (isGenericError) {
              clearInterval(check);
              resolve("__UI_AUTO_GENERIC_ERROR__");
              return;
            }

            const chunks = document.querySelectorAll('ms-text-chunk:not(.user-chunk)');
            
            // ?芣?靽桀儔璈笔�: 憒�? UI ?�??见??�?嚗䔶? Run ?厰??�銁嚗峕???5 蝘㘾?閰阡??𠹺?甈∴??踹? React ?�?蝚砌?甈∠?暺墧?鈭衤辣
            if (chunks.length === 0 && Date.now() - lastRetryTime > 5000) {
                lastRetryTime = Date.now();
                const iconBtn = document.querySelector('button[aria-label*="Run"]');
                if (iconBtn && !iconBtn.disabled) iconBtn.click();
            }
            
            // 敹恍�笔仃?埈???(Fail-fast): 憒�?蝑匧云銋��???见??賣??箔?嚗𣬚凒?交𦆮璉�蒂閫貊䔄?滩岫璈笔�
            const isFlash = targetModelName.includes('flash');
            const failFastLimit = isFlash ? 30000 : 60000;
            if (Date.now() - startTime > failFastLimit && chunks.length === 0) {
              const isGenerating = Array.from(document.querySelectorAll('button')).some(b => b.innerText && b.innerText.includes('Stop')) || 
                                   document.querySelector('button[aria-label*="Stop"]');
                                   
              if (!isGenerating || isFlash) {
                  clearInterval(check);
                  resolve("__UI_AUTO_FAILED_TO_START__");
                  return;
              }
            }

            if (chunks.length > 0) {
              const lastChunk = chunks[chunks.length - 1];
              const text = extractText(lastChunk).trim() || "";
              
              const isGenerating = Array.from(document.querySelectorAll('button')).some(b => b.innerText && b.innerText.includes('Stop')) || 
                                   document.querySelector('button[aria-label*="Stop"]');
                                   
              if (!isGenerating && Date.now() - startTime > 3000) {
                  clearInterval(check);
                  const trimmed = text.trim();
                  if (trimmed.includes("{")) {
                      let openBraces = (trimmed.match(/\{/g) || []).length;
                      let closeBraces = (trimmed.match(/\}/g) || []).length;
                      let openBrackets = (trimmed.match(/\[/g) || []).length;
                      let closeBrackets = (trimmed.match(/\]/g) || []).length;
                      if ((openBraces > 0 && openBraces !== closeBraces) || (openBrackets > 0 && openBrackets !== closeBrackets)) {
                          console.error("[UI Auto] 嚴重異常：檢測到 JSON 括號不對稱，判定為半途截斷！強制進入重試流程！");
                          resolve("__UI_AUTO_GENERIC_ERROR__");
                          return;
                      }
                  }
                  resolve(text);
                  return;
              }

              if (text.length > 0 && text.length === lastLength) {
                unchangedCount++;
                
                const isFlash = targetModelName.includes('flash');
                // 撱園𩑈?⊥香?文??�?嚗𡁜??𨀣糓 Flash 璅∪?銝娍迤?函??琜??�迂?∩?擃㗛? 360 甈?(蝝?180 蝘?嚗屸�?滩???JSON 鋡怠撥?嗆⏛??                const maxUnchanged = isGenerating ? (isFlash ? 360 : 600) : 6;
                if (unchangedCount >= maxUnchanged) {
                  clearInterval(check);
                  if (isGenerating) {
                      // ?�迤?�??𩤃?蝬脤?隞钅𢒰?嗆??⊥香鈭�?銝�?湧＊蝷箸迤?函??琜?雿�??訾??滚??𩤃???                      // ?穃�睲??㕑府?𢠃�坔??芰?撠暹??𧼮�嚗屸�蹱?撠舘稲雿輻鍂?�??滨垢 JSON 閫??撏拇蔑嚗?                      // ?㕑府?湔𦻖銝笔枂?航炊嚗諹?蝟餌絞?芸??�?撣唾??㚚?閰佗?
                      resolve("__UI_AUTO_GENERIC_ERROR__");
                  } else {
                      resolve(text);
                  }
                }
              } else {
                lastLength = text.length;
                unchangedCount = 0;
              }
            }
            
            if (Date.now() - startTime > timeout) {
              clearInterval(check);
              if (chunks.length === 0) {
                  resolve("__UI_AUTO_TIMEOUT_EMPTY__");
              } else {
                  resolve(chunks.length > 0 ? extractText(chunks[chunks.length - 1]).trim() : "");
              }
            }
            
            // Cleanup redundant prohibited check since it's now handled globally at the top of the interval
          }, 500);
        });
      }, {timeout: maxWaitMs, targetModelName: modelName});
      
      if (response === "__UI_AUTO_PROHIBITED_CONTENT__") {
        this.logger.warn("[UI Auto] ?菜葫??Prohibited content (摰匧�撖拇䰻?娍⏛)嚗?);
        throw new Error("PROHIBITED_CONTENT: ?鞟內閰噼◤ Google 摰匧�撖拇䰻?娍⏛??);
      } else if (response === "__UI_AUTO_FAILED_TO_START__") {
        const dumpPath = "C:\\ais2api\\failed_start_dump_" + Date.now() + ".png";
        await this.page.screenshot({ path: dumpPath }).catch(() => {});
        throw new Error("FAILED_TO_START: 40 蝘鍦�?芸�皜砍� AI ?见??肽��??�?嚗峕??拐葉?瑚誑?踹??⊥香??);
      } else if (response === "__UI_AUTO_TIMEOUT_EMPTY__") {
        const dumpPath = "C:\\ais2api\\timeout_empty_dump_" + Date.now() + ".png";
        await this.page.screenshot({ path: dumpPath }).catch(() => {});
        throw new Error("TIMEOUT: AI ?�??�?頞�?蝟餌絞閮剖??�?憭抒?敺�??瓐�?);
      } else if (response === "__UI_AUTO_QUOTA_EXCEEDED__") {
        this.logger.warn("[UI Auto] Quota exceeded or paid API key popup detected! Attempting to close popup.");
        await this.page.evaluate(() => {
            const closeBtn = document.querySelector('button[aria-label="Close"]');
            if (closeBtn) closeBtn.click();
        });
        throw new Error("QUOTA_EXCEEDED: Link a paid API key or Setup billing dialog detected");
      } else if (response === "__UI_AUTO_INTERNAL_ERROR__") {
        this.logger.warn("[UI Auto] Google Internal Error detected! Attempting to close popup.");
        await this.page.evaluate(() => {
            const closeBtn = document.querySelector('button[aria-label="Close"]');
            if (closeBtn) closeBtn.click();
        });
        throw new Error("GOOGLE_INTERNAL_ERROR: An internal error has occurred on Google's backend.");
      }
      
      const finalResponse = response ? response.trim() : "";
      if (finalResponse === "") {
        const dumpPath = "C:\\ais2api\\empty_response_dump_" + Date.now() + ".png";
        await this.page.screenshot({ path: dumpPath }).catch(() => {});
        this.logger.error("[UI Auto] 閫貊䔄 EMPTY_RESPONSE 靽肽風璈笔�嚗峕⏛?硋歇?脣?: " + dumpPath);
        throw new Error("EMPTY_RESPONSE: AI ?噼?鈭�征?賢�摰對?");
      }
      
      // [閫?捱?寞?] ?菔?蝝�?�???AI ?𣂼??�??�??游�摰孵神?交𧋦璈�?獢�?隞乩?撽𡑒?
      try {
          const fs = require('fs');
          const logText = `\n\n=== [${new Date().toISOString()}] ?𣂼??�? (?瑕漲: ${finalResponse.length}) ===\n${finalResponse}\n======================================================\n`;
          fs.appendFileSync('C:\\ais2api\\ai_output_debug.log', logText);
      } catch (logErr) {
          this.logger.error("[UI Auto] 撖怠� debug log 憭望?: " + logErr.message);
      }
      
      this.logger.info("[UI Auto] ?菜葫?啁訜?滩撓?交?摮埈彍: " + finalResponse.length);
      return finalResponse;
    } catch (e) {
      if ((e.message.includes("closed") || e.message.includes("Protocol error")) && retryCount < 1) {
          this.logger.warn("[Browser] ?菜葫?啁雯?�??讛汗?典歇撏拇蔑 (?航�??Cloud Run ?垍蔭銝剜𪃾)嚗峕??坔撥?園??煺蒂?滩岫...");
          this.page = null;
          this.context = null;
          this.browser = null; // 撘瑕�摰��?齿鰵?笔?
          return await this._generateTextViaUIInternal(promptText, modelName, systemInstructions, maxWaitMs, retryCount + 1);
      }
      this.logger.error("[UI Auto] ?潛??啣虜: " + e.message);
      throw e;
    }
  }
}

// ===================================================================================
// PROXY SERVER MODULE
// ===================================================================================

class LoggingService {
  constructor(serviceName = "ProxyServer") {
    this.serviceName = serviceName;
    this.logBuffer = []; // ?其??典?摮䀝葉靽嘥??亙?
    this.maxBufferSize = 100; // ?�憭帋?摮?00??
  }

  _formatMessage(level, message) {
    const d = new Date();
    const pad = (n) => n.toString().padStart(2, '0');
    const timestamp = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${d.getMilliseconds().toString().padStart(3, '0')}`;
    const formatted = `[${level}] ${timestamp} [${this.serviceName}] - ${message}`;

    // 撠�聢撘誩??𡒊??亙?摮睃�蝻枏�??
    this.logBuffer.push(formatted);
    // 憒�?蝻枏�?箄?餈�?憭折鵭摨佗??嗘?憭湧�?𣳇膄?抒??亙?
    if (this.logBuffer.length > this.maxBufferSize) {
      this.logBuffer.shift();
    }

    return formatted;
  }

  info(message) {
    console.log(this._formatMessage("INFO", message));
  }
  error(message) {
    console.error(this._formatMessage("ERROR", message));
  }
  warn(message) {
    console.warn(this._formatMessage("WARN", message));
  }
  debug(message) {
    console.debug(this._formatMessage("DEBUG", message));
  }
}

class MessageQueue extends EventEmitter {
  constructor(timeoutMs = 600000) {
    super();
    this.messages = [];
    this.waitingResolvers = [];
    this.defaultTimeout = timeoutMs;
    this.closed = false;
  }
  enqueue(message) {
    if (this.closed) return;
    if (this.waitingResolvers.length > 0) {
      const resolver = this.waitingResolvers.shift();
      resolver.resolve(message);
    } else {
      this.messages.push(message);
    }
  }
  async dequeue(timeoutMs = this.defaultTimeout) {
    if (this.closed) {
      throw new Error("Queue is closed");
    }
    return new Promise((resolve, reject) => {
      if (this.messages.length > 0) {
        resolve(this.messages.shift());
        return;
      }
      const resolver = { resolve, reject };
      this.waitingResolvers.push(resolver);
      const timeoutId = setTimeout(() => {
        const index = this.waitingResolvers.indexOf(resolver);
        if (index !== -1) {
          this.waitingResolvers.splice(index, 1);
          reject(new Error("Queue timeout"));
        }
      }, timeoutMs);
      resolver.timeoutId = timeoutId;
    });
  }
  close() {
    this.closed = true;
    this.waitingResolvers.forEach((resolver) => {
      clearTimeout(resolver.timeoutId);
      resolver.reject(new Error("Queue closed"));
    });
    this.waitingResolvers = [];
    this.messages = [];
  }
}

class ConnectionRegistry extends EventEmitter {
  constructor(logger) {
    super();
    this.logger = logger;
    this.connections = new Set();
    this.messageQueues = new Map();
    this.reconnectGraceTimer = null; // ?啣?嚗𡁶鍂鈭𡒊??脫?霈⊥𧒄?�??嗅膥
  }
  addConnection(websocket, clientInfo) {
    // --- ?詨?靽格㺿嚗𡁜??啗??亙遣蝡𧢲𧒄嚗峕??文虾?賢??函??𨀣鱏撘�?肽郎??---
    if (this.reconnectGraceTimer) {
      clearTimeout(this.reconnectGraceTimer);
      this.reconnectGraceTimer = null;
      this.logger.info("[Server] ?函??脫??�?瘚见�?啗??伐?撌脣?瘨�鱏撘�憭�???);
    }
    // --- 靽格㺿蝏𤘪? ---

    this.connections.add(websocket);
    websocket.on("message", (data) =>
      this._handleIncomingMessage(data.toString()),
    );
    websocket.on("close", () => this._removeConnection(websocket));
    websocket.on("error", (error) =>
      this.logger.error(`[Server] ?��WebSocket餈墧𦻖?躰秤: ${error.message}`),
    );
    this.emit("connectionAdded", websocket);
  }

  _removeConnection(websocket) {
    this.connections.delete(websocket);
    this.logger.warn("[Server] ?��WebSocket摰Ｘ�蝡航??交鱏撘�??);

    // --- ?詨?靽格㺿嚗帋?蝡见朖皜�??笔?嚗諹�峕糓?臬𢆡銝�銝芰??脫? ---
    this.logger.info("[Server] ?臬𢆡5蝘㘾?餈䂿??脫?...");
    this.reconnectGraceTimer = setTimeout(() => {
      // 5蝘鍦?嚗�??𨀣瓷?㗇鰵餈墧𦻖餈𥟇䔉嚗�朖reconnectGraceTimer?芾◤皜�膄嚗㚁??嗵＆霈斗糓?笔??剖?
      this.logger.error(
        "[Server] 蝻枏�?毺??�??芣?瘚见�?滩??�＆霈方??乩腺憭梧?甇?銁皜�??�?匧?憭�?霂瑟?...",
      );
      this.messageQueues.forEach((queue) => queue.close());
      this.messageQueues.clear();
      this.emit("connectionLost"); // 雿輻鍂銝�銝芣鰵?�?隞嗅?嚗諹”蝷箇＆霈支腺憭?
    }, 10000); // 5蝘垍?蝻枏�?園𡢿

    this.emit("connectionRemoved", websocket);
  }

  _handleIncomingMessage(messageData) {
    try {
      const parsedMessage = JSON.parse(messageData);
      const requestId = parsedMessage.request_id;
      if (!requestId) {
        this.logger.warn("[Server] ?嗅�?䭾?瘨��嚗𡁶撩撠𩹨equest_id");
        return;
      }
      const queue = this.messageQueues.get(requestId);
      if (queue) {
        this._routeMessage(parsedMessage, queue);
      } else {
        // ?函??脫??�??抒?霂瑟??笔??航�隞滨�摮睃銁嚗䔶?餈墧𦻖撌脩??孵?嚗諹??航�隡𡁜紡?湔𪄳銝滚�?笔???
        // ?�𧒄?芾扇敶閗郎?𠺪??踹??删??�辺隞嗉�峕𥁒?踺�?
        this.logger.warn(`[Server] ?嗅�?芰䰻?硋歇餈�𧒄霂瑟?ID?�??? ${requestId}`);
      }
    } catch (error) {
      this.logger.error("[Server] 閫???��WebSocket瘨��憭梯揖");
    }
  }

  // ?嗡??寞? (_routeMessage, hasActiveConnections, getFirstConnection,蝑? 靽脲?銝滚?...
  _routeMessage(message, queue) {
    const { event_type } = message;
    switch (event_type) {
      case "response_headers":
      case "chunk":
      case "error":
        queue.enqueue(message);
        break;
      case "stream_close":
        queue.enqueue({ type: "STREAM_END" });
        break;
      default:
        this.logger.warn(`[Server] ?芰䰻?�??其?隞嗥掩?? ${event_type}`);
    }
  }
  hasActiveConnections() {
    return this.connections.size > 0;
  }
  getFirstConnection() {
    return this.connections.values().next().value;
  }
  createMessageQueue(requestId) {
    const queue = new MessageQueue();
    this.messageQueues.set(requestId, queue);
    return queue;
  }
  removeMessageQueue(requestId) {
    const queue = this.messageQueues.get(requestId);
    if (queue) {
      queue.close();
      this.messageQueues.delete(requestId);
    }
  }
}

class RequestHandler {
  constructor(
    serverSystem,
    connectionRegistry,
    logger,
    browserManager,
    config,
    authSource,
  ) {
    this.serverSystem = serverSystem;
    this.connectionRegistry = connectionRegistry;
    this.logger = logger;
    this.browserManager = browserManager;
    this.config = config;
    this.authSource = authSource;
    this.maxRetries = this.config.maxRetries;
    this.retryDelay = this.config.retryDelay;
    this.failureCount = 0;
    this.usageCount = 0;
    this.isAuthSwitching = false;
    this.needsSwitchingAfterRequest = false;
    this.isSystemBusy = false;
  }

  get currentAuthIndex() {
    return this.browserManager.currentAuthIndex;
  }

  _getMaxAuthIndex() {
    return this.authSource.getMaxIndex();
  }

  _getNextAuthIndex() {
    const available = this.authSource.availableIndices; // 雿輻鍂?啁? availableIndices
    if (available.length === 0) return null;

    const currentIndexInArray = available.indexOf(this.currentAuthIndex);

    if (currentIndexInArray === -1) {
      this.logger.warn(
        `[Auth] 敶枏?蝝Ｗ? ${this.currentAuthIndex} 銝滚銁?舐鍂?𡑒”銝哨?撠�??Ｗ�蝚砌?銝芸虾?函揣撘𨰻��,
      );
      return available[0];
    }

    const nextIndexInArray = (currentIndexInArray + 1) % available.length;
    return available[nextIndexInArray];
  }

  async _switchToNextAuth() {
    const available = this.authSource.availableIndices;

    if (available.length === 0) {
      throw new Error("瘝⊥??舐鍂?�恕霂�?嚗峕?瘜訫??Ｕ�?);
    }

    if (this.isAuthSwitching) {
      this.logger.info("?? [Auth] 甇?銁?�揢/?滚鍳韐血噡嚗諹歲餈�?憭齿?雿?);
      return { success: false, reason: "Switch already in progress." };
    }

    // --- ?𣳇?嚗?---
    this.isSystemBusy = true;
    this.isAuthSwitching = true;

    try {
      // ?閗揭?瑟芋撘?- ?扯??笔𧑐?滚鍳 (Refresh)
      if (available.length === 1) {
        const singleIndex = available[0];
        this.logger.info("==================================================");
        this.logger.info(
          `?? [Auth] ?閗揭?瑟芋撘𧶏?颲曉�頧格揢?��潘?甇?銁?扯??笔𧑐?滚鍳...`,
        );
        this.logger.info(`   ???格?韐血噡: #${singleIndex}`);
        this.logger.info("==================================================");

        try {
          // 撘箏�?齿鰵?㰘蝸敶枏?韐血噡??Context
          await this.browserManager.launchOrSwitchContext(singleIndex);

          // ?喲睸嚗𡁻?蝵株恣?啣膥
          this.failureCount = 0;
          this.usageCount = 0;

          this.logger.info(
            `??[Auth] ?閗揭??#${singleIndex} ?滚鍳/?瑟鰵?𣂼?嚗䔶蝙?刻恣?啣歇皜�妟?�,
          );
          return { success: true, newIndex: singleIndex };
        } catch (error) {
          this.logger.error(`??[Auth] ?閗揭?琿??臬仃韐? ${error.message}`);
          throw error;
        }
      }

      // 憭朞揭?瑟芋撘?- ?扯?頧格揢 (Rotate)

      const previousAuthIndex = this.currentAuthIndex;
      const nextAuthIndex = this._getNextAuthIndex();

      this.logger.info("==================================================");
      this.logger.info(`?? [Auth] 憭朞揭?瑟芋撘𧶏?撘�憪贝揭?瑕??Ｘ?蝔㞗);
      this.logger.info(`   ??敶枏?韐血噡: #${previousAuthIndex}`);
      this.logger.info(`   ???格?韐血噡: #${nextAuthIndex}`);
      this.logger.info("==================================================");

      try {
        await this.browserManager.switchAccount(nextAuthIndex);
        this.failureCount = 0;
        this.usageCount = 0;
        this.logger.info(
          `??[Auth] ?𣂼??�揢?啗揭??#${this.currentAuthIndex}嚗諹恣?啣歇?滨蔭?�,
        );
        return { success: true, newIndex: this.currentAuthIndex };
      } catch (error) {
        this.logger.error(
          `??[Auth] ?�揢?啗揭??#${nextAuthIndex} 憭梯揖: ${error.message}`,
        );
        this.logger.warn(
          `?辶 [Auth] ?�揢憭梯揖嚗峕迤?典?霂訫??�?唬?銝�銝芸虾?刻揭??#${previousAuthIndex}...`,
        );
        try {
          await this.browserManager.launchOrSwitchContext(previousAuthIndex);
          this.logger.info(`??[Auth] ?𣂼??鮋��?啗揭??#${previousAuthIndex}嚗�);
          this.failureCount = 0;
          this.usageCount = 0;
          this.logger.info("[Auth] 憭梯揖?䔶蝙?刻恣?啣歇?典??�?𣂼??𡡞?蝵桐蛹0??);
          return {
            success: false,
            fallback: true,
            newIndex: this.currentAuthIndex,
          };
        } catch (fallbackError) {
          this.logger.error(
            `FATAL: ?𢞖???[Auth] 蝝扳�亙??�?啗揭??#${previousAuthIndex} 銋笔仃韐乩?嚗�??∪虾?賭葉?准��,
          );
          throw fallbackError;
        }
      }
    } finally {
      this.isAuthSwitching = false;
      this.isSystemBusy = false;
    }
  }

  async _switchToSpecificAuth(targetIndex) {
    if (this.isAuthSwitching) {
      this.logger.info("?? [Auth] 甇?銁?�揢韐血噡嚗諹歲餈�?憭齿?雿?);
      return { success: false, reason: "Switch already in progress." };
    }
    if (!this.authSource.availableIndices.includes(targetIndex)) {
      return {
        success: false,
        reason: `?�揢憭梯揖嚗朞揭??#${targetIndex} ?䭾??碶?摮睃銁?�,
      };
    }

    this.isSystemBusy = true;
    this.isAuthSwitching = true;
    try {
      this.logger.info(`?? [Auth] 撘�憪见??Ｗ�?�?韐血噡 #${targetIndex}...`);
      await this.browserManager.switchAccount(targetIndex);
      this.failureCount = 0;
      this.usageCount = 0;
      this.logger.info(
        `??[Auth] ?𣂼??�揢?啗揭??#${this.currentAuthIndex}嚗諹恣?啣歇?滨蔭?�,
      );
      return { success: true, newIndex: this.currentAuthIndex };
    } catch (error) {
      this.logger.error(
        `??[Auth] ?�揢?唳?摰朞揭??#${targetIndex} 憭梯揖: ${error.message}`,
      );
      // 撖嫣??�??�揢嚗�仃韐乩?撠梁凒?交𥁒?辷?銝滩?銵�??�嚗諹悟?冽�?仿?餈嗘葵韐血噡?厰䔮憸?
      throw error;
    } finally {
      this.isAuthSwitching = false;
      this.isSystemBusy = false;
    }
  }

  async _handleRequestFailureAndSwitch(errorDetails, res) {
    // 憭梯揖霈⊥㺭?餉?
    if (this.config.failureThreshold > 0) {
      this.failureCount++;
      this.logger.warn(
        `?𩤃? [Auth] 霂瑟?憭梯揖 - 憭梯揖霈⊥㺭: ${this.failureCount}/${this.config.failureThreshold} (敶枏?韐血噡蝝Ｗ?: ${this.currentAuthIndex})`,
      );
    }

    const isImmediateSwitch = this.config.immediateSwitchStatusCodes.includes(
      errorDetails.status,
    );
    const isThresholdReached =
      this.config.failureThreshold > 0 &&
      this.failureCount >= this.config.failureThreshold;

    // ?芾?皛∟雲隞颱??�揢?∩辣
    if (isImmediateSwitch || isThresholdReached) {
      if (isImmediateSwitch) {
        this.logger.warn(
          `?𣞁 [Auth] ?嗅�?嗆��? ${errorDetails.status}嚗諹圻?𤑳??喳??Ｚ揭??..`,
        );
      } else {
        this.logger.warn(
          `?𣞁 [Auth] 颲曉�憭梯揖?��?(${this.failureCount}/${this.config.failureThreshold})嚗�?憭�??Ｚ揭??..`,
        );
      }

      // [?詨?靽格㺿] 蝑匧??�揢?滢?摰峕?嚗�僎?寞旿?嗥??𨅯??�??峕???
      try {
        await this._switchToNextAuth();
        // 憒�?銝𢠃𢒰餈躰?隞??瘝⊥??𥕦枂?躰秤嚗諹秩?𤾸????鮋��?𣂼?鈭?
        const successMessage = `?? ?格?韐行�?䭾?嚗�歇?芸𢆡?鮋��?唾揭??#${this.currentAuthIndex}?�;
        this.logger.info(`[Auth] ${successMessage}`);
        if (res) this._sendErrorChunkToClient(res, successMessage);
      } catch (error) {
        let userMessage = `???游𦶢?躰秤嚗𡁜??�𧊋?亙??ａ?霂? ${error.message}`;

        if (error.message.includes("Only one account is available")) {
          // ?箸艶嚗𡁜?韐血噡?䭾??�揢
          userMessage = "???�揢憭梯揖嚗𡁜蘨?劐?銝芸虾?刻揭?瑯�?;
          this.logger.info("[Auth] ?芣?銝�銝芸虾?刻揭?瘀?憭梯揖霈⊥㺭撌脤?蝵柴�?);
          this.failureCount = 0;
        } else if (error.message.includes("?鮋��憭梯揖?笔?")) {
          // ?箸艶嚗𡁜??Ｗ�?讛揭?瑕?嚗諹??鮋��?賢仃韐乩?
          userMessage = `???游𦶢?躰秤嚗朞䌊?典??Ｗ?蝝扳�亙??�?�仃韐伐??滚𦛚?航�撌脖葉?哨?霂瑟??交𠯫敹梹?`;
        } else if (error.message.includes("?�揢?啗揭??)) {
          // ?箸艶嚗𡁜??Ｗ�?讛揭?瑕?嚗峕??笔??�嚗�??臭?銝芯憚?𨀣??麨�嘅??祈捶?臭?銝�銝芣?雿𨅯仃韐乩?嚗?
          userMessage = `?𩤃? ?芸𢆡?�揢憭梯揖嚗𡁜歇?芸𢆡?鮋��?啗揭??#${this.currentAuthIndex}嚗諹窈璉�?亦𤌍?�揭?瑟糓?血??券䔮憸塩��;
        }

        this.logger.error(`[Auth] ?𤾸蝱韐血噡?�揢隞餃𦛚?�蝏�仃韐? ${error.message}`);
        if (res) this._sendErrorChunkToClient(res, userMessage);
      }

      return;
    }
  }

  async processRequest(req, res) {
    if (this.browserManager) {
      this.browserManager.notifyUserActivity();
    }
    const requestId = this._generateRequestId();
    res.on("close", () => {
      if (!res.writableEnded) {
        this.logger.warn(
          `[Request] 摰Ｘ�蝡臬歇?𣂼??喲𡡒霂瑟? #${requestId} ?�??乓��,
        );
        this._cancelBrowserRequest(requestId);
      }
    });

    if (!this.connectionRegistry.hasActiveConnections()) {
      if (this.isSystemBusy) {
        this.logger.warn(
          "[System] 璉�瘚见�餈墧𦻖?剖?嚗䔶?蝟餌?甇?銁餈𥡝??�揢/?Ｗ?嚗峕?蝏脲鰵霂瑟???,
        );
        return this._sendErrorResponse(
          res,
          503,
          "?滚𦛚?冽迤?刻?銵�??函輕?歹?韐血噡?�揢/?Ｗ?嚗㚁?霂瑞??𡡞?霂𨰻�?,
        );
      }

      this.logger.error(
        "??[System] 璉�瘚见�瘚讛??汾ebSocket餈墧𦻖撌脫鱏撘�嚗�虾?賣糓餈𤤿?撏拇??�迤?典?霂閙�憭?..",
      );
      // --- 撘�憪𧢲�憭滚?嚗�??�? ---
      this.isSystemBusy = true;
      try {
        await this.browserManager.launchOrSwitchContext(this.currentAuthIndex);
        this.logger.info(`[System] 瘚讛??券△?Ｗ歇?㰘蝸嚗𣬚?敺?WebSocket ?⊥?...`);
        let wsReady = false;
        for (let i = 0; i < 20; i++) {
          if (this.connectionRegistry.hasActiveConnections()) {
            wsReady = true;
            break;
          }
          await new Promise((r) => setTimeout(r, 500));
        }

        if (!wsReady) {
          throw new Error(
            "瘚讛??典歇?臬𢆡嚗䔶??滨垢 WebSocket 憪讠??芾�餈墧𦻖?唬誨?�垢??,
          );
        }
        this.logger.info(`??[System] 瘚讛??其? WebSocket 撌脣??冽�憭滚停蝏迎?`);
      } catch (error) {
        this.logger.error(`??[System] 瘚讛??刻䌊?冽�憭滚仃韐? ${error.message}`);
        return this._sendErrorResponse(
          res,
          503,
          "?滚𦛚?�𧒄銝滚虾?剁??𡒊垢瘚讛??典?靘见援皞�??䭾??芸𢆡?Ｗ?嚗諹窈?𠉛頂蝞∠??塩�?,
        );
      } finally {
        // ?芣?蝖桐縑 WS 餈硺?鈭�??𤥁��蝠摨訫仃韐乩?嚗峕?閫??
        this.isSystemBusy = false;
      }
    }

    if (this.isSystemBusy) {
      this.logger.warn(
        "[System] ?嗅�?啗窈瘙�?雿�頂蝏�迤?刻?銵�????Ｗ?嚗峕?蝏脲鰵霂瑟???,
      );
      return this._sendErrorResponse(
        res,
        503,
        "?滚𦛚?冽迤?刻?銵�??函輕?歹?韐血噡?�揢/?Ｗ?嚗㚁?霂瑞??𡡞?霂𨰻�?,
      );
    }

    const isGenerativeRequest =
      req.method === "POST" &&
      (req.path.includes("generateContent") ||
        req.path.includes("streamGenerateContent"));
    if (this.config.switchOnUses > 0 && isGenerativeRequest) {
      this.usageCount++;
      this.logger.info(
        `[Request] ?�?霂瑟? - 韐血噡頧格揢霈⊥㺭: ${this.usageCount}/${this.config.switchOnUses} (敶枏?韐血噡: ${this.currentAuthIndex})`,
      );
      if (this.usageCount >= this.config.switchOnUses) {
        this.needsSwitchingAfterRequest = true;
      }
    }

    const proxyRequest = this._buildProxyRequest(req, requestId);
    proxyRequest.is_generative = isGenerativeRequest;
    // ?寞旿?斗鱏蝏𤘪?嚗䔶蛹瘚讛??刻??砍?憭�?敹𦯀?
    const messageQueue = this.connectionRegistry.createMessageQueue(requestId);
    const wantsStreamByHeader =
      req.headers.accept && req.headers.accept.includes("text/event-stream");
    const wantsStreamByPath = req.path.includes(":streamGenerateContent");
    const wantsStream = wantsStreamByHeader || wantsStreamByPath;

    try {
      if (wantsStream) {
        // --- 摰Ｘ�蝡舀�閬�?撘誩?摨?---
        this.logger.info(
          `[Request] 摰Ｘ�蝡臬鍳?冽?撘譍?颲?(${this.serverSystem.streamingMode})嚗諹??交?撘誩??�芋撘?..`,
        );
        if (this.serverSystem.streamingMode === "fake") {
          await this._handlePseudoStreamResponse(
            proxyRequest,
            messageQueue,
            req,
            res,
          );
        } else {
          await this._handleRealStreamResponse(proxyRequest, messageQueue, res);
        }
      } else {
        // --- 摰Ｘ�蝡舀�閬�?瘚�??滚? ---
        // ?𡒊＆?羓䰻瘚讛??刻??祆𧋦甈∪??争�靝?甈⊥�克SON?嘅??貨ake璅∪?嚗㗇䔉憭�?
        proxyRequest.streaming_mode = "fake";
        await this._handleNonStreamResponse(proxyRequest, messageQueue, res);
      }
    } catch (error) {
      this._handleRequestError(error, res);
    } finally {
      this.connectionRegistry.removeMessageQueue(requestId);
      if (this.needsSwitchingAfterRequest) {
        this.logger.info(
          `[Auth] 頧格揢霈⊥㺭撌脰噢?啣??ａ???(${this.usageCount}/${this.config.switchOnUses})嚗�??典??啗䌊?典??Ｚ揭??..`,
        );
        this._switchToNextAuth().catch((err) => {
          this.logger.error(`[Auth] ?閧??芸??�?撣唾??�䔄?罸𥲤隤? ${err.message}`);
        });
        this.needsSwitchingAfterRequest = false;
      }
    }
  }

    async processOpenAIRequest(req, res) {
      const abortController = new AbortController();
      req.on('aborted', () => {
          this.logger.warn(`[Adapter] Client aborted the connection prematurely. Aborting queued UI tasks if any.`);
          abortController.abort();
      });

      if (this.browserManager) {
        this.browserManager.notifyUserActivity();
      }
      const requestId = this._generateRequestId();

    // =====================================================================
    // ?璊睃�???圈◢?�?嚙賢???諹�摰?銝𩩍bSocket?潘撓銊餃?嚙??蝞�ㄥ???UI?�⏛??脲慾???
    // =====================================================================

    const isOpenAIStream = req.body.stream === true;
    
    // ?? ?頨啜??䭾?蝟??Python ????嚙質???嘅蕭嚙??藂�?????????菟??瞏准瑪??2.5 ?哨蕭?
    const model = req.body.model || "gemini-2.5-pro"; 
    const systemStreamMode = this.serverSystem.streamingMode;
    const useRealStream = isOpenAIStream && systemStreamMode === "real";

    if (this.config.switchOnUses > 0) {
      this.usageCount++;
      this.logger.info(
        `[Request] OpenAI?嚙??�?? - ?鞱??⊿𡵆?潭𨘻?�𥁒蒪? ${this.usageCount}/${this.config.switchOnUses} (?嗆???鞱??? ${this.currentAuthIndex})`,
      );
      if (this.usageCount >= this.config.switchOnUses) {
        this.needsSwitchingAfterRequest = true;
      }
    }

    let googleBody;
    try {
      googleBody = this._translateOpenAIToGoogle(req.body, model);
    } catch (error) {
      this.logger.error(`[Adapter] OpenAI?�???折???剜０?? ${error.message}`);
      return this._sendErrorResponse(res, 400, "Invalid OpenAI request format");
    }

    let systemInstructionsText = "";
    let formattedPromptText = "";
    if (googleBody.systemInstruction && googleBody.systemInstruction.parts && googleBody.systemInstruction.parts.length > 0) {
        systemInstructionsText = googleBody.systemInstruction.parts.map(p => p.text).join("\n");
    }
    
    for (const content of googleBody.contents) {
        const textParts = content.parts.map(p => p.text).join("\n");
        const role = content.role === "model" ? "Assistant" : "User";
        formattedPromptText += `[${role}]\n${textParts}\n\n`;
    }
    formattedPromptText += `[Assistant]\n`;
    
    const promptText = formattedPromptText.trim();
    const maxWaitMs = 300000; // Increased to 5 minutes for all models to support Thinking mode
    let responseText = "";
    let lastError = null;
    let heartbeatInterval = null;

    if (isOpenAIStream) {
        res.status(200).set({ "Content-Type": "text/event-stream; charset=utf-8", "Cache-Control": "no-cache", "Connection": "keep-alive" });
        res.write(`: keepalive\n\n`); // Send initial heartbeat
        heartbeatInterval = setInterval(() => {
            if (!res.writableEnded) {
                res.write(`: keepalive\n\n`);
            } else {
                clearInterval(heartbeatInterval);
            }
        }, 15000); // 15 seconds
    } else {
        res.status(200).set({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-cache", "Connection": "keep-alive" });
        res.write(` `); // Send initial whitespace heartbeat to keep GCP alive
        heartbeatInterval = setInterval(() => {
            if (!res.writableEnded) {
                res.write(` `);
            } else {
                clearInterval(heartbeatInterval);
            }
        }, 15000); // 15 seconds
    }

    const maxGlobalRetries = 2;
    let hasAppliedJailbreak = false;

    for (let attempt = 1; attempt <= maxGlobalRetries; attempt++) {
        try {
            if (abortController.signal.aborted) throw new Error("CLIENT_DISCONNECTED: Request was aborted before generation could start.");
            responseText = await this.browserManager.generateTextViaUI(promptText, model, systemInstructionsText, maxWaitMs, abortController.signal);
            lastError = null; // Success!
            break; 
        } catch (error) {
            this.logger.error(`[Adapter] 蝚?${attempt} 甈∠??𣂼?閰血仃?? ${error.message}`);
            lastError = error;
            
            let isRecoverable = error.message.includes("QUOTA_EXCEEDED") || error.message.includes("INTERNAL_ERROR") || error.message.includes("FAILED_TO_START") || error.message.includes("EMPTY_RESPONSE") || error.message.includes("Timeout") || error.message.includes("AUTH_EXPIRED"); 
            
            if (error.message.includes("PROHIBITED_CONTENT") && !hasAppliedJailbreak) {
                try {
                    const fs = require('fs');
                    const path = require('path');
                    const jailbreakPath = path.join(process.cwd(), 'jailbreak.txt');
                    if (fs.existsSync(jailbreakPath)) {
                        const jailbreakText = fs.readFileSync(jailbreakPath, 'utf8');
                        if (systemInstructionsText) {
                            systemInstructionsText += "\n\n" + jailbreakText;
                        } else {
                            systemInstructionsText = jailbreakText;
                        }
                        this.logger.warn(`[Adapter] 閫貊䔄摰匧�撖拇䰻嚗�歇瘜典� jailbreak.txt (雿𦦵� System Prompt) 銝行??䠷?閰?..`);
                        hasAppliedJailbreak = true;
                        isRecoverable = true;
                    } else {
                        this.logger.warn(`[Adapter] 閫貊䔄摰匧�撖拇䰻嚗䔶??曆???jailbreak.txt嚗峕𦆮璉�?閰艾��);
                    }
                } catch (err) {
                    this.logger.error(`[Adapter] 瘜典� jailbreak.txt 憭望?: ${err.message}`);
                }
            }
            
            if (isRecoverable && attempt < maxGlobalRetries) {
                this.logger.warn(`[Auth] 閫貊䔄?折�?𤩺??滩岫璈笔�嚗峕迤?典??𥕦董?煺蒂皞硋?蝚?${attempt + 1} 甈∪?閰?..`);
                try {
                    await this._switchToNextAuth();
                } catch (switchErr) {
                    this.logger.error(`[Auth] ?�?撣唾?憭望?: ${switchErr.message}`);
                }
                continue; // ?齿鰵?𡑒岫
            }
            
            // 憒�??舀?敺䔶?甈∪?閰虫??嗅仃?梹??𤥁��糓銝滚銁?舀�敺拇??桀�?�𥲤隤?            if (isRecoverable) {
                this.logger.warn(`[Auth] ?�蝯�?閰虫??嗅仃??(${error.message})嚗峕?摰朞??臬??𥕦董?麄��);
                this._switchToNextAuth().catch(() => {});
            }
            break; // 蝯鞉?餈游?嚗峕??蹱??粹𥲤隤?        }
    }

    if (heartbeatInterval) clearInterval(heartbeatInterval);

    if (lastError) {
        if (res.headersSent) {
            // Already streaming or sent whitespace heartbeat
            if (isOpenAIStream) {
                res.write(`data: ${JSON.stringify({ error: { message: `Internal Server Error: ${lastError.message}` } })}\n\n`);
            } else {
                res.write(JSON.stringify({ error: { code: 500, message: `Internal Server Error: ${lastError.message}`, status: "SERVICE_UNAVAILABLE" } }));
            }
            res.end();
            return;
        } else {
            return this._sendErrorResponse(res, 500, `Internal Server Error: ${lastError.message}`);
        }
    }

    try {
      if (isOpenAIStream) {
        const chunk = { id: `chatcmpl-${requestId}`, object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model: model, choices: [{ delta: { content: responseText }, index: 0, finish_reason: "stop" }] };
        res.write(`data: ${JSON.stringify(chunk)}\n\n`);
        res.write("data: [DONE]\n\n");
        res.end();
      } else {
        const responseJson = { id: `chatcmpl-${requestId}`, object: "chat.completion", created: Math.floor(Date.now() / 1000), model: model, choices: [{ index: 0, message: { role: "assistant", content: responseText }, finish_reason: "stop" }] };
        if (res.headersSent) {
            res.write(JSON.stringify(responseJson));
            res.end();
        } else {
            res.status(200).json(responseJson);
        }
      }
    } catch (error) {
      this.logger.error(`[Adapter] 撖怠�?墧??�䔄?罸𥲤隤? ${error.message}`);
      if (!res.headersSent) {
        return this._sendErrorResponse(res, 500, `Internal Server Error: ${error.message}`);
      }
    }

    if (this.needsSwitchingAfterRequest) {
      this._switchToNextAuth().catch((err) => {
        this.logger.error(`[Auth] ?閧??芸??�?撣唾??�䔄?罸𥲤隤? ${err.message}`);
      });
      this.needsSwitchingAfterRequest = false;
    }
  }

  _cancelBrowserRequest(requestId) {
    const connection = this.connectionRegistry.getFirstConnection();
    if (connection) {
      this.logger.info(
        `[Request] 甇?銁?烐?閫�膥?煾��?瘨�窈瘙?#${requestId} ?�?隞?..`,
      );
      connection.send(
        JSON.stringify({
          event_type: "cancel_request",
          request_id: requestId,
        }),
      );
    } else {
      this.logger.warn(
        `[Request] ?䭾??煾��?瘨�?隞歹?瘝⊥??舐鍂?�?閫�膥WebSocket餈墧𦻖?�,
      );
    }
  }

  _generateRequestId() {
    return `${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
  }
  _buildProxyRequest(req, requestId) {
    let bodyObj = req.body;
    if (
      this.serverSystem.forceThinking &&
      req.method === "POST" &&
      bodyObj &&
      bodyObj.contents
    ) {
      if (!bodyObj.generationConfig) {
        bodyObj.generationConfig = {};
      }

      if (!bodyObj.generationConfig.thinkingConfig) {
        this.logger.info(
          `[Proxy] ?𩤃? (Google?毺??澆?) 撘箏�?函?撌脣鍳?剁?銝𥪜恥?瑞垢?芣?靘偦?蝵殷?甇?銁瘜典� thinkingConfig...`,
        );
        bodyObj.generationConfig.thinkingConfig = { includeThoughts: true };
      } else {
        this.logger.info(
          `[Proxy] ??(Google?毺??澆?) 璉�瘚见�摰Ｘ�蝡航䌊撣行綫?�?蝵殷?頝唾?撘箏�瘜典�?�,
        );
      }
    }

    let requestBody = "";
    if (bodyObj) {
      requestBody = JSON.stringify(bodyObj);
    }

    return {
      path: req.path,
      method: req.method,
      headers: req.headers,
      query_params: req.query,
      body: requestBody,
      request_id: requestId,
      streaming_mode: this.serverSystem.streamingMode,
    };
  }
  _forwardRequest(proxyRequest) {
    const connection = this.connectionRegistry.getFirstConnection();
    if (connection) {
      connection.send(JSON.stringify(proxyRequest));
    } else {
      throw new Error("?䭾?頧砍?霂瑟?嚗𡁏瓷?匧虾?函?WebSocket餈墧𦻖??);
    }
  }
  _sendErrorChunkToClient(res, errorMessage) {
    const errorPayload = {
      error: {
        message: `[隞??蝟餌??鞟內] ${errorMessage}`,
        type: "proxy_error",
        code: "proxy_error",
      },
    };
    const chunk = `data: ${JSON.stringify(errorPayload)}\n\n`;
    if (res && !res.writableEnded) {
      res.write(chunk);
      this.logger.info(`[Request] 撌脣?摰Ｘ�蝡臬??�??�?霂臭縑?? ${errorMessage}`);
    }
  }

  async _handlePseudoStreamResponse(proxyRequest, messageQueue, req, res) {
    this.logger.info(
      "[Request] 摰Ｘ�蝡臬鍳?冽?撘譍?颲?(fake)嚗諹??乩憚瘚�?憭�?璅∪?...",
    );
    res.status(200).set({
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    });
    const connectionMaintainer = setInterval(() => {
      if (!res.writableEnded) res.write(": keep-alive\n\n");
    }, 3000);

    try {
      let lastMessage,
        requestFailed = false;

      // ?睲賑?�?霂訫儐?荔??喃蝙?芾?銝�甈∴?
      for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
        if (attempt > 1) {
          this.logger.info(
            `[Request] 霂瑟?撠肽? #${attempt}/${this.maxRetries}...`,
          );
        }
        this._forwardRequest(proxyRequest);
        try {
          const timeoutPromise = new Promise((_, reject) =>
            setTimeout(
              () =>
                reject(
                  new Error(
                    "Response from browser timed out after 300 seconds",
                  ),
                ),
              300000,
            ),
          );
          lastMessage = await Promise.race([
            messageQueue.dequeue(),
            timeoutPromise,
          ]);
        } catch (timeoutError) {
          this.logger.error(`[Request] ?游𦶢?躰秤: ${timeoutError.message}`);
          lastMessage = {
            event_type: "error",
            status: 504,
            message: timeoutError.message,
          };
        }

        if (lastMessage.event_type === "error") {
          // --- ?詨?靽格㺿嚗𡁜銁餈䠷?撠勗躹?�??踹??枏㫲銝滚?閬�??𨅯仃韐乒�脲𠯫敹?---
          if (
            !(
              lastMessage.message &&
              lastMessage.message.includes("The user aborted a request")
            )
          ) {
            // ?芣??其??胼�𦦵鍂?瑕?瘨��萘??��銝页??齿??售�𨅯?霂訫仃韐乒�萘?霅血?
            this.logger.warn(
              `[Request] 撠肽? #${attempt} 憭梯揖: ?嗅� ${
                lastMessage.status || "?芰䰻"
              } ?躰秤??- ${lastMessage.message}`,
            );
          }

          if (attempt < this.maxRetries) {
            await new Promise((resolve) =>
              setTimeout(resolve, this.retryDelay),
            );
            continue;
          }
          requestFailed = true;
        }
        break;
      }

      // 憭�??�蝏�???
      if (requestFailed) {
        if (
          lastMessage.message &&
          lastMessage.message.includes("The user aborted a request")
        ) {
          this.logger.info(
            `[Request] 霂瑟? #${proxyRequest.request_id} 撌脩眏?冽�憒亙??𡝗?嚗䔶?霈∪�憭梯揖蝏蠘恣?�,
          );
        } else {
          this.logger.error(
            `[Request] ?�??${this.maxRetries} 甈⊿?霂訫?憭梯揖嚗�?霈∪�憭梯揖蝏蠘恣?�,
          );
          await this._handleRequestFailureAndSwitch(lastMessage, res);
          this._sendErrorChunkToClient(
            res,
            `霂瑟??�蝏�仃韐? ${lastMessage.message}`,
          );
        }
        return;
      }

      // ?𣂼??��餉?
      if (proxyRequest.is_generative && this.failureCount > 0) {
        this.logger.info(
          `??[Auth] ?�?霂瑟??𣂼? - 憭梯揖霈⊥㺭撌脖? ${this.failureCount} ?滨蔭銝?0`,
        );
        this.failureCount = 0;
      }
      const dataMessage = await messageQueue.dequeue();
      const endMessage = await messageQueue.dequeue();
      if (dataMessage.data) {
        res.write(`data: ${dataMessage.data}\n\n`);
      }
      if (endMessage.type !== "STREAM_END") {
        this.logger.warn("[Request] ?芣𤣰?圈??毺?瘚�??煺縑?瑯�?);
      }
      try {
        const fullResponse = JSON.parse(dataMessage.data);
        const finishReason =
          fullResponse.candidates?.[0]?.finishReason || "UNKNOWN";
        this.logger.info(
          `??[Request] ?滚?蝏𤘪?嚗�??? ${finishReason}嚗諹窈瘙�D: ${proxyRequest.request_id}`,
        );
      } catch (e) {}
      res.write("data: [DONE]\n\n");
    } catch (error) {
      this._handleRequestError(error, res);
    } finally {
      clearInterval(connectionMaintainer);
      if (!res.writableEnded) {
        res.end();
      }
      this.logger.info(
        `[Request] ?滚?憭�?蝏𤘪?嚗諹窈瘙�D: ${proxyRequest.request_id}`,
      );
    }
  }

  async _handleRealStreamResponse(proxyRequest, messageQueue, res) {
    this.logger.info(`[Request] 霂瑟?撌脫晷?𤑳?瘚讛??函垢憭�?...`);
    this._forwardRequest(proxyRequest);
    const headerMessage = await messageQueue.dequeue();

    if (headerMessage.event_type === "error") {
      if (
        headerMessage.message &&
        headerMessage.message.includes("The user aborted a request")
      ) {
        this.logger.info(
          `[Request] 霂瑟? #${proxyRequest.request_id} 撌脰◤?冽�憒亙??𡝗?嚗䔶?霈∪�憭梯揖蝏蠘恣?�,
        );
      } else {
        this.logger.error(`[Request] 霂瑟?憭梯揖嚗�?霈∪�憭梯揖蝏蠘恣?�);
        await this._handleRequestFailureAndSwitch(headerMessage, null);
        return this._sendErrorResponse(
          res,
          headerMessage.status,
          headerMessage.message,
        );
      }
      if (!res.writableEnded) res.end();
      return;
    }

    // --- ?詨?靽格㺿嚗𡁜蘨?匧銁?�?霂瑟??𣂼??塚??漤?蝵桀仃韐亥恣??---
    if (proxyRequest.is_generative && this.failureCount > 0) {
      this.logger.info(
        `??[Auth] ?�?霂瑟??𣂼? - 憭梯揖霈⊥㺭撌脖? ${this.failureCount} ?滨蔭銝?0`,
      );
      this.failureCount = 0;
    }
    // --- 靽格㺿蝏𤘪? ---

    this._setResponseHeaders(res, headerMessage);
    this.logger.info("[Request] 撘�憪𧢲?撘譍?颲?..");
    try {
      let lastChunk = "";
      while (true) {
        const dataMessage = await messageQueue.dequeue(30000);
        if (dataMessage.type === "STREAM_END") {
          this.logger.info("[Request] ?嗅�瘚�??煺縑?瑯�?);
          break;
        }
        if (dataMessage.data) {
          res.write(dataMessage.data);
          lastChunk = dataMessage.data;
        }
      }
      try {
        if (lastChunk.startsWith("data: ")) {
          const jsonString = lastChunk.substring(6).trim();
          if (jsonString) {
            const lastResponse = JSON.parse(jsonString);
            const finishReason =
              lastResponse.candidates?.[0]?.finishReason || "UNKNOWN";
            this.logger.info(
              `??[Request] ?滚?蝏𤘪?嚗�??? ${finishReason}嚗諹窈瘙�D: ${proxyRequest.request_id}`,
            );
          }
        }
      } catch (e) {}
    } catch (error) {
      if (error.message !== "Queue timeout") throw error;
      this.logger.warn("[Request] ?�?撘誩?摨磰??塚??航�瘚�歇甇?虜蝏𤘪???);
    } finally {
      if (!res.writableEnded) res.end();
      this.logger.info(
        `[Request] ?�?撘誩?摨磰??亙歇?喲𡡒嚗諹窈瘙�D: ${proxyRequest.request_id}`,
      );
    }
  }

  async _handleNonStreamResponse(proxyRequest, messageQueue, res) {
    this.logger.info(`[Request] 餈𥕦�?墧?撘誩??�芋撘?..`);

    // 頧砍?霂瑟??唳?閫�膥蝡?
    this._forwardRequest(proxyRequest);

    try {
      // 1. 蝑匧??滚?憭港縑??
      const headerMessage = await messageQueue.dequeue();
      if (headerMessage.event_type === "error") {
        // ... (?躰秤憭�??餉?靽脲?銝滚?)
        if (headerMessage.message?.includes("The user aborted a request")) {
          this.logger.info(
            `[Request] 霂瑟? #${proxyRequest.request_id} 撌脰◤?冽�憒亙??𡝗??�,
          );
        } else {
          this.logger.error(
            `[Request] 瘚讛??函垢餈𥪜??躰秤: ${headerMessage.message}`,
          );
          await this._handleRequestFailureAndSwitch(headerMessage, null);
        }
        return this._sendErrorResponse(
          res,
          headerMessage.status || 500,
          headerMessage.message,
        );
      }

      // 2. ?�?銝�銝芰??脣躹嚗�僎蝖桐?敺芰㴓蝑匧??游�?嗅�蝏𤘪?靽∪噡
      let fullBody = "";
      while (true) {
        const message = await messageQueue.dequeue(300000);
        if (message.type === "STREAM_END") {
          this.logger.info("[Request] ?嗅�蝏𤘪?靽∪噡嚗峕㺭?格𦻖?嗅?瘥𨰻�?);
          break;
        }
        if (message.event_type === "chunk" && message.data) {
          fullBody += message.data;
        }
      }

      // 3. ?滨蔭憭梯揖霈⊥㺭?剁?憒�??�閬�?
      if (proxyRequest.is_generative && this.failureCount > 0) {
        this.logger.info(
          `??[Auth] ?墧?撘讐??鞱窈瘙�???- 憭梯揖霈⊥㺭撌脖? ${this.failureCount} ?滨蔭銝?0`,
        );
        this.failureCount = 0;
      }

      // [?詨?靽格迤] 撖逼oogle?毺??澆??�?摨磰?銵峕惣?賢㦛?�???
      try {
        let parsedBody = JSON.parse(fullBody);
        let needsReserialization = false;

        const candidate = parsedBody.candidates?.[0];
        if (candidate?.content?.parts) {
          const imagePartIndex = candidate.content.parts.findIndex(
            (p) => p.inlineData,
          );

          if (imagePartIndex > -1) {
            this.logger.info(
              "[Proxy] 璉�瘚见�Google?澆??滚?銝剔??曄??唳旿嚗峕迤?刻蓮?Ｖ蛹Markdown...",
            );
            const imagePart = candidate.content.parts[imagePartIndex];
            const image = imagePart.inlineData;

            // ?𥕦遣銝�銝芣鰵??text part ?交𤜯?Ｗ??亦? inlineData part
            const markdownTextPart = {
              text: `![Generated Image](data:${image.mimeType};base64,${image.data})`,
            };

            // ?踵揢?匧??亦??典?
            candidate.content.parts[imagePartIndex] = markdownTextPart;
            needsReserialization = true;
          }
        }

        if (needsReserialization) {
          fullBody = JSON.stringify(parsedBody); // 憒�?憭�?鈭�㦛?�??齿鰵摨誩???
        }
      } catch (e) {
        this.logger.warn(
          `[Proxy] ?滚?雿㮖??舀??�?JSON嚗峕??典??�㦛?�𧒄?粹?: ${e.message}`,
        );
        // 憒�??粹?嚗�?隞�銋��銝滚?嚗𣬚凒?亙??�?憪讠? fullBody
      }

      try {
        const fullResponse = JSON.parse(fullBody);
        const finishReason =
          fullResponse.candidates?.[0]?.finishReason || "UNKNOWN";
        this.logger.info(
          `??[Request] ?滚?蝏𤘪?嚗�??? ${finishReason}嚗諹窈瘙�D: ${proxyRequest.request_id}`,
        );
      } catch (e) {}

      // 4. 霈曄蔭甇?＆?�SON?滚?憭湛?撟嗡?甈⊥�批??�??�??��?冽㺭??      if (res.headersSent) {
          res.write(fullBody || "{}");
          res.end();
      } else {
          res
            .status(headerMessage.status || 200)
            .type("application/json")
            .send(fullBody || "{}");
      }

      this.logger.info(`[Request] 撌脣?摰Ｘ�蝡臬??�??渡??墧?撘誩?摨𢛵��);
    } catch (error) {
      this._handleRequestError(error, res);
    }
  }

  _getKeepAliveChunk(req) {
    if (req.path.includes("chat/completions")) {
      const payload = {
        id: `chatcmpl-${this._generateRequestId()}`,
        object: "chat.completion.chunk",
        created: Math.floor(Date.now() / 1000),
        model: "gpt-4",
        choices: [{ index: 0, delta: {}, finish_reason: null }],
      };
      return `data: ${JSON.stringify(payload)}\n\n`;
    }
    if (
      req.path.includes("generateContent") ||
      req.path.includes("streamGenerateContent")
    ) {
      const payload = {
        candidates: [
          {
            content: { parts: [{ text: "" }], role: "model" },
            finishReason: null,
            index: 0,
            safetyRatings: [],
          },
        ],
      };
      return `data: ${JSON.stringify(payload)}\n\n`;
    }
    return "data: {}\n\n";
  }

  _setResponseHeaders(res, headerMessage) {
    res.status(headerMessage.status || 200);
    const headers = headerMessage.headers || {};
    Object.entries(headers).forEach(([name, value]) => {
      if (name.toLowerCase() !== "content-length") res.set(name, value);
    });
  }
  _handleRequestError(error, res) {
    if (res.headersSent) {
      this.logger.error(`[Request] 霂瑟?憭�??躰秤 (憭游歇?煾�?: ${error.message}`);
      if (this.serverSystem.streamingMode === "fake")
        this._sendErrorChunkToClient(res, `憭�?憭梯揖: ${error.message}`);
      if (!res.writableEnded) res.end();
    } else {
      this.logger.error(`[Request] 霂瑟?憭�??躰秤: ${error.message}`);
      const status = error.message.includes("頞�𧒄") ? 504 : 500;
      this._sendErrorResponse(res, status, `隞???躰秤: ${error.message}`);
    }
  }

  _sendErrorResponse(res, status, message) {
    if (!res.headersSent) {
      // 1. ?𥕦遣銝�銝芰泵?㇁PI閫�??�SON?躰秤撖寡情
      const errorPayload = {
        error: {
          code: status || 500,
          message: message,
          status: "SERVICE_UNAVAILABLE", // 餈蹱糓銝�銝芰內靘讠𠶖?�?
        },
      };
      // 2. 霈曄蔭?滚?蝐餃?銝?application/json 撟嗅???
      res
        .status(status || 500)
        .type("application/json")
        .send(JSON.stringify(errorPayload));
    }
  }

  _translateOpenAIToGoogle(openaiBody, modelName = "") {
    this.logger.info("[Adapter] 撘�憪见?OpenAI霂瑟??澆?蝧餉?銝慘oogle?澆?...");

    let systemInstruction = null;
    const googleContents = [];

    // 1. ?�氖??system ?�誘
    const systemMessages = openaiBody.messages.filter(
      (msg) => msg.role === "system",
    );
    if (systemMessages.length > 0) {
      // 撠�???system message ?�?摰孵?撟?
      const systemContent = systemMessages.map((msg) => msg.content).join("\n");
      systemInstruction = {
        // Google Gemini 1.5 Pro 撘�憪𧢲迤撘𤩺𣈲??system instruction
        role: "system",
        parts: [{ text: systemContent }],
      };
    }

    // 2. 頧祆揢 user ??assistant 瘨��
    const conversationMessages = openaiBody.messages.filter(
      (msg) => msg.role !== "system",
    );
    for (const message of conversationMessages) {
      const googleParts = [];

      // [?詨??寡?] ?斗鱏 content ?臬?蝚虫葡餈䀹糓?啁?
      if (typeof message.content === "string") {
        // a. 憒�??舐滲?�𧋦
        googleParts.push({ text: message.content });
      } else if (Array.isArray(message.content)) {
        // b. 憒�??臬㦛?�毽?�?摰?
        for (const part of message.content) {
          if (part.type === "text") {
            googleParts.push({ text: part.text });
          } else if (part.type === "image_url" && part.image_url) {
            // 隞?data URL 銝剜???mimetype ??base64 ?唳旿
            const dataUrl = part.image_url.url;
            const match = dataUrl.match(/^data:(image\/.*?);base64,(.*)$/);
            if (match) {
              googleParts.push({
                inlineData: {
                  mimeType: match[1],
                  data: match[2],
                },
              });
            }
          }
        }
      }

      googleContents.push({
        role: message.role === "assistant" ? "model" : "user",
        parts: googleParts,
      });
    }

    // 3. ?�遣?�蝏�?Google霂瑟?雿?
    const googleRequest = {
      contents: googleContents,
      ...(systemInstruction && {
        systemInstruction: { parts: systemInstruction.parts },
      }),
    };

    // 4. 頧祆揢?�??�㺭
    const generationConfig = {
      temperature: openaiBody.temperature,
      topP: openaiBody.top_p,
      topK: openaiBody.top_k,
      maxOutputTokens: openaiBody.max_tokens,
      stopSequences: openaiBody.stop,
    };

    const extraBody = openaiBody.extra_body || {};
    let rawThinkingConfig =
      extraBody.google?.thinking_config ||
      extraBody.google?.thinkingConfig ||
      extraBody.thinkingConfig ||
      extraBody.thinking_config ||
      openaiBody.thinkingConfig ||
      openaiBody.thinking_config;

    let thinkingConfig = null;

    if (rawThinkingConfig) {
      // 2. ?澆?皜�?嚗𡁜? snake_case (銝见?蝥? 頧祆揢銝?camelCase (撽澆陸)
      thinkingConfig = {};

      // 憭�?撘�??
      if (rawThinkingConfig.include_thoughts !== undefined) {
        thinkingConfig.includeThoughts = rawThinkingConfig.include_thoughts;
      } else if (rawThinkingConfig.includeThoughts !== undefined) {
        thinkingConfig.includeThoughts = rawThinkingConfig.includeThoughts;
      }

      // 憭�? Budget (憸�?)
      // if (rawThinkingConfig.thinking_budget !== undefined) {
      // thinkingConfig.thinkingBudgetTokenLimit =
      // rawThinkingConfig.thinking_budget;
      //} else if (rawThinkingConfig.thinkingBudget !== undefined) {
      //thinkingConfig.thinkingBudgetTokenLimit =
      //rawThinkingConfig.thinkingBudget;
      //}

      this.logger.info(
        `[Adapter] ?𣂼??𣂼?撟嗉蓮?Ｘ綫?�?蝵? ${JSON.stringify(thinkingConfig)}`,
      );
    }

    // 3. 憒�?瘝⊥𪄳?圈?蝵殷?撠肽?霂�� OpenAI ?�??�㺭 'reasoning_effort'
    if (!thinkingConfig) {
      const effort = openaiBody.reasoning_effort || extraBody.reasoning_effort;
      if (effort) {
        this.logger.info(
          `[Adapter] 璉�瘚见� OpenAI ?�??函??�㺭 (reasoning_effort: ${effort})嚗諹䌊?刻蓮?Ｖ蛹 Google ?澆??�,
        );
        thinkingConfig = { includeThoughts: true };
      }
    }

    // 4. 撘箏�撘�?舫�餉? (WebUI撘�??
    if (this.serverSystem.forceThinking && !thinkingConfig) {
      this.logger.info(
        "[Adapter] ?𩤃? 撘箏�?函?撌脣鍳?剁?銝𥪜恥?瑞垢?芣?靘偦?蝵殷?甇?銁瘜典� thinkingConfig...",
      );
      thinkingConfig = { includeThoughts: true };
    }

    // 5. ?坔�?�蝏�?蝵?
    if (thinkingConfig) {
      generationConfig.thinkingConfig = thinkingConfig;
    }

    googleRequest.generationConfig = generationConfig;

    // 5. 摰匧�霈曄蔭
    googleRequest.safetySettings = [
      { category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_NONE" },
      { category: "HARM_CATEGORY_HATE_SPEECH", threshold: "BLOCK_NONE" },
      { category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold: "BLOCK_NONE" },
      { category: "HARM_CATEGORY_DANGEROUS_CONTENT", threshold: "BLOCK_NONE" },
    ];

    this.logger.info("[Adapter] 蝧餉?摰峕???);
    return googleRequest;
  }

  _translateGoogleToOpenAIStream(googleChunk, modelName = "gemini-pro") {
    if (!googleChunk || googleChunk.trim() === "") {
      return null;
    }

    let jsonString = googleChunk;
    if (jsonString.startsWith("data: ")) {
      jsonString = jsonString.substring(6).trim();
    }

    if (!jsonString || jsonString === "[DONE]") return null;

    let googleResponse;
    try {
      googleResponse = JSON.parse(jsonString);
    } catch (e) {
      this.logger.warn(`[Adapter] ?䭾?閫??Google餈𥪜??�SON?? ${jsonString}`);
      return null;
    }

    const candidate = googleResponse.candidates?.[0];
    if (!candidate) {
      if (googleResponse.promptFeedback) {
        this.logger.warn(
          `[Adapter] Google餈𥪜?鈭�romptFeedback嚗�虾?賢歇鋡急㜃?? ${JSON.stringify(
            googleResponse.promptFeedback,
          )}`,
        );
        const errorText = `[ProxySystem Error] Request blocked due to safety settings. Finish Reason: ${googleResponse.promptFeedback.blockReason}`;
        return `data: ${JSON.stringify({
          id: `chatcmpl-${this._generateRequestId()}`,
          object: "chat.completion.chunk",
          created: Math.floor(Date.now() / 1000),
          model: modelName,
          choices: [
            { index: 0, delta: { content: errorText }, finish_reason: "stop" },
          ],
        })}\n\n`;
      }
      return null;
    }

    const delta = {};

    if (candidate.content && Array.isArray(candidate.content.parts)) {
      const imagePart = candidate.content.parts.find((p) => p.inlineData);

      if (imagePart) {
        const image = imagePart.inlineData;
        delta.content = `![Generated Image](data:${image.mimeType};base64,${image.data})`;
        this.logger.info("[Adapter] 隞擧?撘誩?摨𥪜?銝剜??蠘圾?𣂼�?曄???);
      } else {
        // ?滚??�?厰�?�??�氖?肽��?摰孵?甇???�捆
        let contentAccumulator = "";
        let reasoningAccumulator = "";

        for (const part of candidate.content.parts) {
          // Google API ??thought ?�扇
          if (part.thought === true) {
            reasoningAccumulator += part.text || "";
          } else {
            contentAccumulator += part.text || "";
          }
        }

        // ?芣?敶𤘪??�捆?嗆?瘛餃???delta 銝?
        if (reasoningAccumulator) {
          delta.reasoning_content = reasoningAccumulator;
        }
        if (contentAccumulator) {
          delta.content = contentAccumulator;
        }
      }
    }

    // 憒�?瘝⊥?隞颱??�捆?䀹凒嚗�?銝滩??墧㺭?殷??踹?蝛箄?嚗?
    if (!delta.content && !delta.reasoning_content && !candidate.finishReason) {
      return null;
    }

    const openaiResponse = {
      id: `chatcmpl-${this._generateRequestId()}`,
      object: "chat.completion.chunk",
      created: Math.floor(Date.now() / 1000),
      model: modelName,
      choices: [
        {
          index: 0,
          delta: delta, // 雿輻鍂?�鉄 reasoning_content ??delta
          finish_reason: candidate.finishReason || null,
        },
      ],
    };

    return `data: ${JSON.stringify(openaiResponse)}\n\n`;
  }
}

class ProxyServerSystem extends EventEmitter {
  constructor() {
    super();
    this.logger = new LoggingService("ProxySystem");
    this._loadConfiguration(); // 餈嗘葵?賣㺭隡𡁏�銵䔶??Ｙ?_loadConfiguration
    this.streamingMode = this.config.streamingMode;

    this.forceThinking = false;

    this.authSource = new AuthSource(this.logger);
    this.browserManager = new BrowserManager(
      this.logger,
      this.config,
      this.authSource,
    );
    this.connectionRegistry = new ConnectionRegistry(this.logger);
    this.requestHandler = new RequestHandler(
      this,
      this.connectionRegistry,
      this.logger,
      this.browserManager,
      this.config,
      this.authSource,
    );

    this.httpServer = null;
    this.wsServer = null;
  }

  // ===== ?�?匧遆?圈�撌脫迤蝖格𦆮蝵桀銁蝐餃???=====

  _loadConfiguration() {
    let config = {
      httpPort: 7860,
      host: "0.0.0.0",
      wsPort: 9998,
      streamingMode: "real",
      failureThreshold: 3,
      switchOnUses: 40,
      maxRetries: 1,
      retryDelay: 2000,
      browserExecutablePath: null,
      apiKeys: [],
      immediateSwitchStatusCodes: [429, 503],
      // [?啣?] ?其?餈質葵API撖�𤨎?交?
      apiKeySource: "?芾挽蝵?,
      targetUrl: "https://ai.studio/apps/59d6e5ae-e3bb-494d-b942-2da1adab2ba0",
    };

    const configPath = path.join(__dirname, "config.json");
    try {
      if (fs.existsSync(configPath)) {
        const fileConfig = JSON.parse(fs.readFileSync(configPath, "utf-8"));
        config = { ...config, ...fileConfig };
        this.logger.info("[System] 撌脖? config.json ?㰘蝸?滨蔭??);
      }
    } catch (error) {
      this.logger.warn(`[System] ?䭾?霂餃??𤥁圾??config.json: ${error.message}`);
    }

    if (process.env.PORT)
      config.httpPort = parseInt(process.env.PORT, 10) || config.httpPort;
    if (process.env.HOST) config.host = process.env.HOST;
    if (process.env.TARGET_URL) config.targetUrl = process.env.TARGET_URL;
    if (process.env.STREAMING_MODE)
      config.streamingMode = process.env.STREAMING_MODE;
    if (process.env.FAILURE_THRESHOLD)
      config.failureThreshold =
        parseInt(process.env.FAILURE_THRESHOLD, 10) || config.failureThreshold;
    if (process.env.SWITCH_ON_USES)
      config.switchOnUses =
        parseInt(process.env.SWITCH_ON_USES, 10) || config.switchOnUses;
    if (process.env.MAX_RETRIES)
      config.maxRetries =
        parseInt(process.env.MAX_RETRIES, 10) || config.maxRetries;
    if (process.env.RETRY_DELAY)
      config.retryDelay =
        parseInt(process.env.RETRY_DELAY, 10) || config.retryDelay;
    if (process.env.CAMOUFOX_EXECUTABLE_PATH)
      config.browserExecutablePath = process.env.CAMOUFOX_EXECUTABLE_PATH;
    if (process.env.API_KEYS) {
      config.apiKeys = process.env.API_KEYS.split(",");
    }

    let rawCodes = process.env.IMMEDIATE_SWITCH_STATUS_CODES;
    let codesSource = "?臬??㗛?";

    if (
      !rawCodes &&
      config.immediateSwitchStatusCodes &&
      Array.isArray(config.immediateSwitchStatusCodes)
    ) {
      rawCodes = config.immediateSwitchStatusCodes.join(",");
      codesSource = "config.json ?�辣?㚚?霈文�?;
    }

    if (rawCodes && typeof rawCodes === "string") {
      config.immediateSwitchStatusCodes = rawCodes
        .split(",")
        .map((code) => parseInt(String(code).trim(), 10))
        .filter((code) => !isNaN(code) && code >= 400 && code <= 599);
      if (config.immediateSwitchStatusCodes.length > 0) {
        this.logger.info(`[System] 撌脖? ${codesSource} ?㰘蝸?𦦵??喳??Ｘ𥁒?嗵??腈��);
      }
    } else {
      config.immediateSwitchStatusCodes = [];
    }

    if (Array.isArray(config.apiKeys)) {
      config.apiKeys = config.apiKeys
        .map((k) => String(k).trim())
        .filter((k) => k);
    } else {
      config.apiKeys = [];
    }

    // [靽格㺿] ?湔鰵API撖�𤨎?交??�ế?剝�餉?
    if (config.apiKeys.length > 0) {
      config.apiKeySource = "?芸?銋?;
    } else {
      config.apiKeys = ["123456"];
      config.apiKeySource = "暺䁅恕";
      this.logger.info("[System] ?芾挽蝵桐遙雿𧭈PI Key嚗�歇?舐鍂暺䁅恕撖�?: 123456");
    }

    const modelsPath = path.join(__dirname, "models.json");
    try {
      if (fs.existsSync(modelsPath)) {
        const modelsFileContent = fs.readFileSync(modelsPath, "utf-8");
        config.modelList = JSON.parse(modelsFileContent); // 撠�粉?硋�?�芋?见?銵典??卉onfig撖寡情
        this.logger.info(
          `[System] 撌脖? models.json ?𣂼??㰘蝸 ${config.modelList.length} 銝芣芋?卝��,
        );
      } else {
        this.logger.warn(
          `[System] ?芣𪄳??models.json ?�辣嚗�?雿輻鍂暺䁅恕璅∪??𡑒”?�,
        );
        config.modelList = ["gemini-1.5-pro-latest"]; // ?𣂷?銝�銝芸??冽芋?页??脫迫?滚𦛚?臬𢆡憭梯揖
      }
    } catch (error) {
      this.logger.error(
        `[System] 霂餃??𤥁圾??models.json 憭梯揖: ${error.message}嚗�?雿輻鍂暺䁅恕璅∪??𡑒”?�,
      );
      config.modelList = ["gemini-1.5-pro-latest"]; // ?粹??嗡?雿輻鍂憭�鍂璅∪?
    }

    this.config = config;
    this.logger.info("================ [ ?�??滨蔭 ] ================");
    this.logger.info(`  HTTP ?滚𦛚蝡臬藁: ${this.config.httpPort}`);
    this.logger.info(`  ?穃𨯬?啣?: ${this.config.host}`);
    this.logger.info(`  瘚�?璅∪?: ${this.config.streamingMode}`);
    this.logger.info(
      `  頧格揢霈⊥㺭?�揢?��? ${
        this.config.switchOnUses > 0
          ? `瘥?${this.config.switchOnUses} 甈∟窈瘙�??�揢`
          : "撌脩???
      }`,
    );
    this.logger.info(
      `  憭梯揖霈⊥㺭?�揢: ${
        this.config.failureThreshold > 0
          ? `憭梯揖${this.config.failureThreshold} 甈∪??�揢`
          : "撌脩???
      }`,
    );
    this.logger.info(
      `  蝡见朖?�揢?仿??? ${
        this.config.immediateSwitchStatusCodes.length > 0
          ? this.config.immediateSwitchStatusCodes.join(", ")
          : "撌脩???
      }`,
    );
    this.logger.info(`  ?閙活霂瑟??�憭折?霂? ${this.config.maxRetries}甈︶);
    this.logger.info(`  ?滩??湧?: ${this.config.retryDelay}ms`);
    this.logger.info(`  API 撖�𤨎?交?: ${this.config.apiKeySource}`); // ?典鍳?冽𠯫敹𦯀葉銋�遬蝷箏枂??
    this.logger.info(
      "=============================================================",
    );
  }

  async start(initialAuthIndex = null) {
    this.logger.info("[System] 撘�憪见撕?批鍳?冽?蝔?..");
    const allAvailableIndices = this.authSource.availableIndices;

    if (allAvailableIndices.length === 0) {
      throw new Error("瘝⊥?隞颱??舐鍂?�恕霂�?嚗峕?瘜訫鍳?具�?);
    }

    let startupOrder = [...allAvailableIndices];
    if (initialAuthIndex && allAvailableIndices.includes(initialAuthIndex)) {
      this.logger.info(`[System] 璉�瘚见�?�??臬𢆡蝝Ｗ? #${initialAuthIndex}嚗�?隡睃?撠肽??�);
      startupOrder = [
        initialAuthIndex,
        ...allAvailableIndices.filter((i) => i !== initialAuthIndex),
      ];
    } else {
      if (initialAuthIndex) {
        this.logger.warn(`[System] ?�??�鍳?函揣撘?#${initialAuthIndex} ?䭾??碶??舐鍂嚗�??厰?霈日◇摨誩鍳?具��);
      }
      this.logger.info(`[System] ?芣?摰𡁏??�鍳?函揣撘𤏪?撠�?暺䁅恕憿箏? [${startupOrder.join(", ")}] 撠肽??�);
    }


    let isStarted = false;
    this.logger.info("[System] ?�??㰘蝸瘚讛??函㴓憓?..");

    // 雿輻鍂 UI ?�俈甇Ｗ銁?臬𢆡?罸𡢿?㕑窈瘙�僎?𤏸圻?烐?閫�膥?滚鍳
    const unlock = await this.browserManager._acquireUiLock();
    try {
      for (const index of startupOrder) {
        try {
          this.logger.info(`[System] 撠肽?雿輻鍂韐血噡 #${index} ?臬𢆡?滚𦛚...`);
          await this.browserManager.launchOrSwitchContext(index);
          isStarted = true;
          this.logger.info(`[System] ??雿輻鍂韐血噡 #${index} ?𣂼??臬𢆡嚗�);
          break;
        } catch (error) {
          this.logger.error(`[System] ??雿輻鍂韐血噡 #${index} ?臬𢆡憭梯揖?�??? ${error.message}`);
        }
      }
    } finally {
      unlock();
    }

    if (!isStarted) {
      throw new Error("?�?㕑恕霂�??�?霂訫仃韐伐??滚𦛚?冽?瘜訫鍳?具�?);
    }

    this.logger.info("[System] 瘚讛??函㴓憓�歇撠梁貌嚗峕迤?典鍳??HTTP/WS ?滚𦛚?冽𦻖?嗅??刻窈瘙?..");
    await this._startHttpServer();
    await this._startWebSocketServer();

    this.logger.info(`[System] 隞???滚𦛚?函頂蝏笔??典鍳?典??僐��);
    this.emit("started");
  }

  _createAuthMiddleware() {
    const basicAuth = require("basic-auth"); // 蝖桐?甇方?摮睃銁嚗䔶蛹admin霈方??𣂷??舀?

    return (req, res, next) => {
      const serverApiKeys = this.config.apiKeys;
      if (!serverApiKeys || serverApiKeys.length === 0) {
        return next();
      }

      let clientKey = null;
      if (req.headers["x-goog-api-key"]) {
        clientKey = req.headers["x-goog-api-key"];
      } else if (
        req.headers.authorization &&
        req.headers.authorization.startsWith("Bearer ")
      ) {
        clientKey = req.headers.authorization.substring(7);
      } else if (req.headers["x-api-key"]) {
        clientKey = req.headers["x-api-key"];
      } else if (req.query.key) {
        clientKey = req.query.key;
      }

      if (clientKey && serverApiKeys.includes(clientKey)) {
        this.logger.info(
          `[Auth] API Key撉諹??朞? (?亥䌊: ${
            req.headers["x-forwarded-for"] || req.ip
          })`,
        );
        if (req.query.key) {
          delete req.query.key;
        }
        return next();
      }

      // 撖嫣?瘝⊥??㗇?API Key?�窈瘙�?餈𥪜?401?躰秤
      // 瘜冽?嚗𡁜�摨瑟??亦??餉?撌脣銁_createExpressApp銝剜??滚???
      if (req.path !== "/favicon.ico") {
        const clientIp = req.headers["x-forwarded-for"] || req.ip;
        this.logger.warn(
          `[Auth] 霈輸䔮撖�??躰秤?𣇉撩憭梧?撌脫?蝏肽窈瘙���P: ${clientIp}, Path: ${req.path}`,
        );
      }

      return res.status(401).json({
        error: {
          message:
            "Access denied. A valid API key was not found or is incorrect.",
        },
      });
    };
  }

  async _startHttpServer() {
    const app = this._createExpressApp();
    this.httpServer = http.createServer(app);

    this.httpServer.keepAliveTimeout = 300000;
    this.httpServer.headersTimeout = 305000;
    this.httpServer.requestTimeout = 300000;

    return new Promise((resolve) => {
      this.httpServer.listen(this.config.httpPort, this.config.host, () => {
        this.logger.info(
          `[System] HTTP?滚𦛚?典歇??http://${this.config.host}:${this.config.httpPort} 銝羓??柄,
        );
        this.logger.info(
          `[System] Keep-Alive 頞�𧒄撌脰挽蝵桐蛹 ${
            this.httpServer.keepAliveTimeout / 1000
          } 蝘鉝��,
        );
        resolve();
      });
    });
  }

  _createExpressApp() {
    const app = express();

    app.use((req, res, next) => {
      res.header("Access-Control-Allow-Origin", "*");
      res.header(
        "Access-Control-Allow-Methods",
        "GET, POST, PUT, DELETE, PATCH, OPTIONS",
      );
      res.header(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization, x-requested-with, x-api-key, x-goog-api-key, origin, accept",
      );
      if (req.method === "OPTIONS") {
        return res.sendStatus(204);
      }
      next();
    });

    app.use((req, res, next) => {
      if (
        req.path !== "/api/status" &&
        req.path !== "/" &&
        req.path !== "/favicon.ico" &&
        req.path !== "/login"
      ) {
        this.logger.info(
          `[Entrypoint] ?嗅�銝�銝芾窈瘙? ${req.method} ${req.path}`,
        );
      }
      next();
    });
    app.use(express.json({ limit: "100mb" }));
    app.use(express.urlencoded({ extended: true }));

    const sessionSecret =
      // Section 1 & 2 (?詨?銝剝𡢿隞嗅??餃?頝舐眏) 靽脲?銝滚?...
      (this.config.apiKeys && this.config.apiKeys[0]) ||
      crypto.randomBytes(20).toString("hex");
    app.use(cookieParser());
    app.use(
      session({
        secret: sessionSecret,
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false, maxAge: 86400000 },
      }),
    );
    const isAuthenticated = (req, res, next) => {
      if (req.session.isAuthenticated) {
        return next();
      }
      res.redirect("/login");
    };
    app.get("/login", (req, res) => {
      if (req.session.isAuthenticated) {
        return res.redirect("/");
      }
      const loginHtml = `
      <!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>?餃?</title>
      <style>body{display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;background:#f0f2f5}form{background:white;padding:40px;border-radius:10px;box-shadow:0 4px 8px rgba(0,0,0,0.1);text-align:center}input{width:250px;padding:10px;margin-top:10px;border:1px solid #ccc;border-radius:5px}button{width:100%;padding:10px;background-color:#007bff;color:white;border:none;border-radius:5px;margin-top:20px;cursor:pointer}.error{color:red;margin-top:10px}</style>
      </head><body><form action="/login" method="post"><h2>霂瑁???API Key</h2>
      <input type="password" name="apiKey" placeholder="API Key" required autofocus><button type="submit">?餃?</button>
      ${
        req.query.error ? '<p class="error">API Key ?躰秤!</p>' : ""
      }</form></body></html>`;
      res.send(loginHtml);
    });
    app.post("/login", (req, res) => {
      const { apiKey } = req.body;
      if (apiKey && this.config.apiKeys.includes(apiKey)) {
        req.session.isAuthenticated = true;
        res.redirect("/");
      } else {
        res.redirect("/login?error=1");
      }
    });

    // ==========================================================
    // Section 3: ?嗆��△????API (?�蝏�?)
    // ==========================================================
    app.get("/", isAuthenticated, (req, res) => {
      const { config, requestHandler, authSource, browserManager } = this;
      const initialIndices = authSource.initialIndices || [];
      const availableIndices = authSource.availableIndices || [];
      const invalidIndices = initialIndices.filter(
        (i) => !availableIndices.includes(i),
      );
      const logs = this.logger.logBuffer || [];

      const accountNameMap = authSource.accountNameMap;
      const accountDetailsHtml = initialIndices
        .map((index) => {
          const isInvalid = invalidIndices.includes(index);
          const name = isInvalid
            ? "N/A (JSON?澆??躰秤)"
            : accountNameMap.get(index) || "N/A (?芸𦶢??";
          return `<span class="label" style="padding-left: 20px;">韐血噡${index}</span>: ${name}`;
        })
        .join("\n");

      const accountOptionsHtml = availableIndices
        .map((index) => `<option value="${index}">韐血噡 #${index}</option>`)
        .join("");

      const statusHtml = `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>隞???滚𦛚?嗆�?/title>
        <style>
        body { font-family: 'SF Mono', 'Consolas', 'Menlo', monospace; background-color: #f0f2f5; color: #333; padding: 2em; }
        .container { max-width: 800px; margin: 0 auto; background: #fff; padding: 1em 2em 2em 2em; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h1, h2 { color: #333; border-bottom: 2px solid #eee; padding-bottom: 0.5em;}
        pre { background: #2d2d2d; color: #f0f0f0; font-size: 1.1em; padding: 1.5em; border-radius: 8px; white-space: pre-wrap; word-wrap: break-word; line-height: 1.6; }
        #log-container { font-size: 0.9em; max-height: 400px; overflow-y: auto; }
        .status-ok { color: #2ecc71; font-weight: bold; }
        .status-error { color: #e74c3c; font-weight: bold; }
        .label { display: inline-block; width: 220px; box-sizing: border-box; }
        .dot { height: 10px; width: 10px; background-color: #bbb; border-radius: 50%; display: inline-block; margin-left: 10px; animation: blink 1s infinite alternate; }
        @keyframes blink { from { opacity: 0.3; } to { opacity: 1; } }
        .action-group { display: flex; flex-wrap: wrap; gap: 15px; align-items: center; }
        .action-group button, .action-group select { font-size: 1em; border: 1px solid #ccc; padding: 10px 15px; border-radius: 8px; cursor: pointer; transition: background-color 0.3s ease; }
        .action-group button:hover { opacity: 0.85; }
        .action-group button { background-color: #007bff; color: white; border-color: #007bff; }
        .action-group select { background-color: #ffffff; color: #000000; -webkit-appearance: none; appearance: none; }
        @media (max-width: 600px) {
            body { padding: 0.5em; }
            .container { padding: 1em; margin: 0; }
            pre { padding: 1em; font-size: 0.9em; }
            .label { width: auto; display: inline; }
            .action-group { flex-direction: column; align-items: stretch; }
            .action-group select, .action-group button { width: 100%; box-sizing: border-box; }
        }
        </style>
    </head>
    <body>
        <div class="container">
        <h1>隞???滚𦛚?嗆�?<span class="dot" title="?唳旿?冽���?唬葉..."></span></h1>
        <div id="status-section">
            <pre>
<span class="label">?滚𦛚?嗆�?/span>: <span class="status-ok">Running</span>
<span class="label">瘚讛??刻???/span>: <span class="${
        browserManager.browser ? "status-ok" : "status-error"
      }">${!!browserManager.browser}</span>
--- ?滚𦛚?滨蔭 ---
<span class="label">瘚�芋撘?/span>: ${
        config.streamingMode
      } (隞�鍳?冽?撘譍?颲𤘪𧒄?�?)
<span class="label">撘箏�?函?</span>: ${
        this.forceThinking ? "??撌脣鍳?? : "??撌脣�??
      }
<span class="label">蝡见朖?�揢 (?嗆��?)</span>: ${
        config.immediateSwitchStatusCodes.length > 0
          ? `[${config.immediateSwitchStatusCodes.join(", ")}]`
          : "撌脩???
      }
<span class="label">API 撖�𤨎</span>: ${config.apiKeySource}
--- 韐血噡?嗆�?---
<span class="label">敶枏?雿輻鍂韐血噡</span>: #${requestHandler.currentAuthIndex}
<span class="label">雿輻鍂甈⊥㺭霈⊥㺭</span>: ${requestHandler.usageCount} / ${
        config.switchOnUses > 0 ? config.switchOnUses : "N/A"
      }
<span class="label">餈䂿賒憭梯揖霈⊥㺭</span>: ${requestHandler.failureCount} / ${
        config.failureThreshold > 0 ? config.failureThreshold : "N/A"
      }
<span class="label">?急??啁??餃???/span>: [${initialIndices.join(
        ", ",
      )}] (?餅㺭: ${initialIndices.length})
      ${accountDetailsHtml}
<span class="label">?澆??躰秤 (撌脣蕭??</span>: [${invalidIndices.join(
        ", ",
      )}] (?餅㺭: ${invalidIndices.length})
            </pre>
        </div>
        <div id="actions-section" style="margin-top: 2em;">
            <h2>?滢??Ｘ踎</h2>
            <div class="action-group">
                <select id="accountIndexSelect">${accountOptionsHtml}</select>
                <button onclick="switchSpecificAccount()">?�揢韐血噡</button>
                <button onclick="toggleStreamingMode()">?�揢瘚�芋撘?/button>
                <button onclick="toggleForceThinking()">?�揢撘箏�?函?</button>
            </div>
        </div>
        <div id="log-section" style="margin-top: 2em;">
            <h2>摰墧𧒄?亙? (?�餈?${logs.length} ??</h2>
            <pre id="log-container">${logs.join("\n")}</pre>
        </div>
        </div>
        <script>
        function updateContent() {
            fetch('/api/status').then(response => response.json()).then(data => {
                const statusPre = document.querySelector('#status-section pre');
                const accountDetailsHtml = data.status.accountDetails.map(acc => {
                  return '<span class="label" style="padding-left: 20px;">韐血噡' + acc.index + '</span>: ' + acc.name;
                }).join('\\n');
                statusPre.innerHTML = 
                    '<span class="label">?滚𦛚?嗆�?/span>: <span class="status-ok">Running</span>\\n' +
                    '<span class="label">瘚讛??刻???/span>: <span class="' + (data.status.browserConnected ? "status-ok" : "status-error") + '">' + data.status.browserConnected + '</span>\\n' +
                    '--- ?滚𦛚?滨蔭 ---\\n' +
                    '<span class="label">瘚�芋撘?/span>: ' + data.status.streamingMode + '\\n' +
                    '<span class="label">撘箏�?函?</span>: ' + data.status.forceThinking + '\\n' +
                    '<span class="label">蝡见朖?�揢 (?嗆��?)</span>: ' + data.status.immediateSwitchStatusCodes + '\\n' +
                    '<span class="label">API 撖�𤨎</span>: ' + data.status.apiKeySource + '\\n' +
                    '--- 韐血噡?嗆�?---\\n' +
                    '<span class="label">敶枏?雿輻鍂韐血噡</span>: #' + data.status.currentAuthIndex + '\\n' +
                    '<span class="label">雿輻鍂甈⊥㺭霈⊥㺭</span>: ' + data.status.usageCount + '\\n' +
                    '<span class="label">餈䂿賒憭梯揖霈⊥㺭</span>: ' + data.status.failureCount + '\\n' +
                    '<span class="label">?急??啁??餉揭??/span>: ' + data.status.initialIndices + '\\n' +
                    accountDetailsHtml + '\\n' +
                    '<span class="label">?澆??躰秤 (撌脣蕭??</span>: ' + data.status.invalidIndices;
                
                const logContainer = document.getElementById('log-container');
                const logTitle = document.querySelector('#log-section h2');
                const isScrolledToBottom = logContainer.scrollHeight - logContainer.clientHeight <= logContainer.scrollTop + 1;
                logTitle.innerText = \`摰墧𧒄?亙? (?�餈?\${data.logCount} ??\`;
                logContainer.innerText = data.logs;
                if (isScrolledToBottom) { logContainer.scrollTop = logContainer.scrollHeight; }
            }).catch(error => console.error('Error fetching new content:', error));
        }

        function switchSpecificAccount() {
            const selectElement = document.getElementById('accountIndexSelect');
            const targetIndex = selectElement.value;
            if (!confirm(\`蝖桀?閬�??Ｗ�韐血噡 #\${targetIndex} ?梹?餈嗘??滨蔭瘚讛??其?霂腈��`)) {
                return;
            }
            fetch('/api/switch-account', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ targetIndex: parseInt(targetIndex, 10) })
            })
            .then(res => res.text()).then(data => { alert(data); updateContent(); })
            .catch(err => { 
                if (err.message.includes('Load failed') || err.message.includes('NetworkError')) {
                    alert('?𩤃? 瘚讛??典鍳?刻??ｇ??滢?隞滚銁?𤾸蝱餈𥡝?銝准��\n\\n霂瑚?閬�?憭滨�?颯�?);
                } else {
                    alert('???滢?憭梯揖: ' + err); 
                }
                updateContent(); 
            });
        }
            
        function toggleStreamingMode() { 
            const newMode = prompt('霂瑁??交鰵?�?璅∪? (real ??fake):', '${
              this.config.streamingMode
            }');
            if (newMode === 'fake' || newMode === 'real') {
                fetch('/api/set-mode', { 
                    method: 'POST', 
                    headers: { 'Content-Type': 'application/json' }, 
                    body: JSON.stringify({ mode: newMode }) 
                })
                .then(res => res.text()).then(data => { alert(data); updateContent(); })
                .catch(err => alert('霈曄蔭憭梯揖: ' + err));
            } else if (newMode !== null) { 
                alert('?䭾??�芋撘𧶏?霂瑕蘨颲枏� "real" ??"fake"??); 
            } 
        }

        function toggleForceThinking() {
            fetch('/api/toggle-force-thinking', { 
                method: 'POST', 
                headers: { 'Content-Type': 'application/json' }
            })
            .then(res => res.text()).then(data => { alert(data); updateContent(); })
            .catch(err => alert('霈曄蔭憭梯揖: ' + err));
        }

        document.addEventListener('DOMContentLoaded', () => {
            updateContent(); 
            setInterval(updateContent, 5000);
        });
        </script>
    </body>
    </html>
    `;
      res.status(200).send(statusHtml);
    });

    // TEMPORARY DIAGNOSTIC ENDPOINT - check what "Prohibited" text exists on the page
    app.get("/api/diagnose-prohibited", async (req, res) => {
      try {
        if (!browserManager || !browserManager.page) {
          return res.status(500).json({ error: "No browser page available" });
        }
        const results = await browserManager.page.evaluate(() => {
          const bodyText = document.body.innerText;
          const matches = [];
          const searchTerm = 'Prohibited';
          let idx = 0;
          while (true) {
            idx = bodyText.indexOf(searchTerm, idx);
            if (idx === -1) break;
            const start = Math.max(0, idx - 150);
            const end = Math.min(bodyText.length, idx + searchTerm.length + 150);
            matches.push({ position: idx, context: bodyText.substring(start, end) });
            idx += searchTerm.length;
          }
          const elementMatches = [];
          document.querySelectorAll('*').forEach(el => {
            if (el.children.length === 0 && el.innerText && el.innerText.includes('Prohibited')) {
              elementMatches.push({
                tag: el.tagName, className: el.className, id: el.id,
                role: el.getAttribute('role'), ariaLabel: el.getAttribute('aria-label'),
                parentTag: el.parentElement?.tagName, parentClass: el.parentElement?.className,
                grandparentTag: el.parentElement?.parentElement?.tagName, 
                grandparentClass: el.parentElement?.parentElement?.className,
                text: el.innerText.substring(0, 500)
              });
            }
          });
          return { bodyLength: bodyText.length, totalMatches: matches.length, matches, elementMatches };
        });
        // Also take a screenshot
        const screenshotPath = "C:\\ais2api\\diagnose_prohibited_" + Date.now() + ".png";
        await browserManager.page.screenshot({ path: screenshotPath });
        results.screenshot = screenshotPath;
        res.status(200).json(results);
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    app.get("/api/status", isAuthenticated, (req, res) => {
      const { config, requestHandler, authSource, browserManager } = this;
      const initialIndices = authSource.initialIndices || [];
      const invalidIndices = initialIndices.filter(
        (i) => !authSource.availableIndices.includes(i),
      );
      const logs = this.logger.logBuffer || [];
      const accountNameMap = authSource.accountNameMap;
      const accountDetails = initialIndices.map((index) => {
        const isInvalid = invalidIndices.includes(index);
        const name = isInvalid
          ? "N/A (JSON?澆??躰秤)"
          : accountNameMap.get(index) || "N/A (?芸𦶢??";
        return { index, name };
      });

      const data = {
        status: {
          streamingMode: `${this.streamingMode} (隞�鍳?冽?撘譍?颲𤘪𧒄?�?)`,
          forceThinking: this.forceThinking ? "??撌脣鍳?? : "??撌脣�??,
          browserConnected: !!browserManager.browser,
          immediateSwitchStatusCodes:
            config.immediateSwitchStatusCodes.length > 0
              ? `[${config.immediateSwitchStatusCodes.join(", ")}]`
              : "撌脩???,
          apiKeySource: config.apiKeySource,
          currentAuthIndex: requestHandler.currentAuthIndex,
          usageCount: `${requestHandler.usageCount} / ${
            config.switchOnUses > 0 ? config.switchOnUses : "N/A"
          }`,
          failureCount: `${requestHandler.failureCount} / ${
            config.failureThreshold > 0 ? config.failureThreshold : "N/A"
          }`,
          initialIndices: `[${initialIndices.join(", ")}] (?餅㺭: ${
            initialIndices.length
          })`,
          accountDetails: accountDetails,
          invalidIndices: `[${invalidIndices.join(", ")}] (?餅㺭: ${
            invalidIndices.length
          })`,
        },
        logs: logs.join("\n"),
        logCount: logs.length,
      };
      res.json(data);
    });
    app.post("/api/switch-account", isAuthenticated, async (req, res) => {
      try {
        const { targetIndex } = req.body;
        if (targetIndex !== undefined && targetIndex !== null) {
          this.logger.info(
            `[WebUI] ?嗅�?�揢?唳?摰朞揭??#${targetIndex} ?�窈瘙?..`,
          );
          const result =
            await this.requestHandler._switchToSpecificAuth(targetIndex);
          if (result.success) {
            res.status(200).send(`?�揢?𣂼?嚗�歇瞈�瘣餉揭??#${result.newIndex}?�);
          } else {
            res.status(400).send(result.reason);
          }
        } else {
          this.logger.info("[WebUI] ?嗅�?见𢆡?�揢銝衤?銝芾揭?瑞?霂瑟?...");
          if (this.authSource.availableIndices.length <= 1) {
            return res
              .status(400)
              .send("?�揢?滢?撌脣?瘨�??芣?銝�銝芸虾?刻揭?瘀??䭾??�揢??);
          }
          const result = await this.requestHandler._switchToNextAuth();
          if (result.success) {
            res
              .status(200)
              .send(`?�揢?𣂼?嚗�歇?�揢?啗揭??#${result.newIndex}?�);
          } else if (result.fallback) {
            res
              .status(200)
              .send(`?�揢憭梯揖嚗䔶?撌脫??笔??�?啗揭??#${result.newIndex}?�);
          } else {
            res.status(409).send(`?滢??芣�銵? ${result.reason}`);
          }
        }
      } catch (error) {
        res
          .status(500)
          .send(`?游𦶢?躰秤嚗𡁏?雿𨅯仃韐伐?霂瑟??交𠯫敹𨰜��?霂? ${error.message}`);
      }
    });
    app.post("/api/set-mode", isAuthenticated, (req, res) => {
      const newMode = req.body.mode;
      if (newMode === "fake" || newMode === "real") {
        this.streamingMode = newMode;
        this.logger.info(
          `[WebUI] 瘚�?璅∪?撌脩眏霈方??冽�?�揢銝? ${this.streamingMode}`,
        );
        res.status(200).send(`瘚�?璅∪?撌脣??Ｖ蛹: ${this.streamingMode}`);
      } else {
        res.status(400).send('?䭾?璅∪?. 霂瑞鍂 "fake" ??"real".');
      }
    });

    app.post("/api/toggle-force-thinking", isAuthenticated, (req, res) => {
      this.forceThinking = !this.forceThinking;
      const statusText = this.forceThinking ? "撌脣鍳?? : "撌脣�??;
      this.logger.info(`[WebUI] 撘箏�?函?撘�?喳歇?�揢銝? ${statusText}`);
      res.status(200).send(`撘箏�?函?璅∪?: ${statusText}`);
    });

    app.use(this._createAuthMiddleware());

    app.get("/v1/models", (req, res) => {
      const modelIds = this.config.modelList || ["gemini-2.5-pro"];

      const models = modelIds.map((id) => ({
        id: id,
        object: "model",
        created: Math.floor(Date.now() / 1000),
        owned_by: "google",
      }));

      res.status(200).json({
        object: "list",
        data: models,
      });
    });

    app.post("/v1/chat/completions", (req, res) => {
      this.requestHandler.processOpenAIRequest(req, res);
    });
    app.all(/(.*)/, (req, res) => {
      this.requestHandler.processRequest(req, res);
    });

    return app;
  }

  async _startWebSocketServer() {
    this.wsServer = new WebSocket.Server({
      port: this.config.wsPort,
      host: this.config.host,
    });
    this.wsServer.on("connection", (ws, req) => {
      this.connectionRegistry.addConnection(ws, {
        address: req.socket.remoteAddress,
      });
    });
  }
}

// ===================================================================================
// MAIN INITIALIZATION
// ===================================================================================

async function initializeServer() {
  const initialAuthIndex = parseInt(process.env.INITIAL_AUTH_INDEX, 10) || 1;
  try {
    const serverSystem = new ProxyServerSystem();
    await serverSystem.start(initialAuthIndex);
  } catch (error) {
    console.error("???滚𦛚?典鍳?典仃韐?", error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  initializeServer();
}

module.exports = { ProxyServerSystem, BrowserManager, initializeServer };

