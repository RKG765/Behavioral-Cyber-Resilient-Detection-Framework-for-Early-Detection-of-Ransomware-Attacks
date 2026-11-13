// how/app.js - Interactive Controller for the Telltale Presentation Site

document.addEventListener("DOMContentLoaded", () => {
  // 1. Initialize Mermaid.js
  if (typeof mermaid !== "undefined") {
    mermaid.initialize({
      startOnLoad: true,
      theme: 'dark',
      themeVariables: {
        darkMode: true,
        background: '#0E1626',
        primaryColor: '#111C2E',
        primaryBorderColor: '#00E5FF',
        primaryTextColor: '#F8FAFC',
        lineColor: '#64748B',
        secondaryColor: '#16233B',
        tertiaryColor: '#131E32'
      }
    });
  }

  // 2. Accordion Interactions (Evaluator Grilling Mode)
  document.querySelectorAll(".accordion-header").forEach(header => {
    header.addEventListener("click", () => {
      const item = header.parentElement;
      item.classList.toggle("open");
    });
  });

  // 3. Scrollspy Navbar Tracking
  const sections = document.querySelectorAll("section.chapter");
  const navLinks = document.querySelectorAll("nav.chapter-nav .nav-pills a");

  window.addEventListener("scroll", () => {
    let current = "";
    sections.forEach(section => {
      const sectionTop = section.offsetTop - 120;
      if (window.pageYOffset >= sectionTop) {
        current = section.getAttribute("id");
      }
    });

    navLinks.forEach(link => {
      link.classList.remove("active");
      if (link.getAttribute("href") === `#${current}`) {
        link.classList.add("active");
      }
    });
  });

  // 4. Interactive Diagram View Switcher (Image vs Mermaid)
  window.switchDiagramView = function(containerId, viewMode) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const imgView = container.querySelector(".diagram-img-view");
    const mmView = container.querySelector(".diagram-mermaid-view");
    const buttons = container.querySelectorAll(".view-toggle-btn");

    buttons.forEach(btn => btn.classList.remove("active"));

    if (viewMode === 'image') {
      if (imgView) imgView.style.display = "block";
      if (mmView) mmView.style.display = "none";
      const btn = container.querySelector("[data-mode='image']");
      if (btn) btn.classList.add("active");
    } else {
      if (imgView) imgView.style.display = "none";
      if (mmView) mmView.style.display = "flex";
      const btn = container.querySelector("[data-mode='mermaid']");
      if (btn) btn.classList.add("active");
    }
  };

  // 5. Image Lightbox / Zoom
  const modal = document.getElementById("imgLightboxModal");
  const modalImg = document.getElementById("lightboxImage");
  const modalCaption = document.getElementById("lightboxCaption");
  const closeBtn = document.querySelector(".lightbox-close");

  document.querySelectorAll(".zoomable-diagram").forEach(img => {
    img.addEventListener("click", () => {
      if (modal && modalImg) {
        modal.style.display = "flex";
        modalImg.src = img.src;
        if (modalCaption) modalCaption.textContent = img.alt || "Architectural Schematic";
      }
    });
  });

  if (closeBtn) {
    closeBtn.addEventListener("click", () => {
      if (modal) modal.style.display = "none";
    });
  }
  if (modal) {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) modal.style.display = "none";
    });
  }

  // 6. Interactive Process Lifecycle Simulator
  window.runInteractiveSimulation = function(scenario) {
    const steps = [
      { id: "sim-step-1", name: "1. Process Intercept (WMI / ETW Hook)", delay: 300 },
      { id: "sim-step-2", name: "2. Fast-Path Gating (L1A WinTrust / L1B SQLite)", delay: 600 },
      { id: "sim-step-3", name: "3. 30s Behavioral Window (99 Heuristics Extracted)", delay: 900 },
      { id: "sim-step-4", name: "4. Tier 1 ONNX Single-Core Inference", delay: 1200 },
      { id: "sim-step-5", name: "5. Tier 2 Cloud ResNet Brain Escalation", delay: 1600 },
      { id: "sim-step-6", name: "6. Final Decision & Containment Directive", delay: 2000 }
    ];

    const resultBox = document.getElementById("simResultDisplay");
    const progressList = document.getElementById("simProgressList");
    if (!resultBox || !progressList) return;

    progressList.innerHTML = "";
    resultBox.style.display = "none";

    let stepIdx = 0;
    function nextStep() {
      if (stepIdx < steps.length) {
        const s = steps[stepIdx];
        const li = document.createElement("div");
        li.className = "sim-progress-item active";
        li.innerHTML = `<span class="sim-spinner">⏳</span> <strong>${s.name}</strong>`;
        progressList.appendChild(li);

        setTimeout(() => {
          li.classList.remove("active");
          li.classList.add("completed");
          li.querySelector(".sim-spinner").innerHTML = "✓";
          stepIdx++;
          nextStep();
        }, 350);
      } else {
        // Complete
        renderSimulationOutcome(scenario, resultBox);
      }
    }
    nextStep();
  };

  function renderSimulationOutcome(scenario, resultBox) {
    resultBox.style.display = "block";
    if (scenario === 'benign') {
      resultBox.innerHTML = `
        <div class="sim-outcome-card allow">
          <div class="outcome-badge allow">VERDICT: LOCAL ALLOW (BENIGN)</div>
          <h4>Process: notepad_custom.exe (PID: 248102)</h4>
          <p><strong>Tier 1 Score:</strong> 0.0341 (Threshold &le; 0.10)</p>
          <p><strong>Latency:</strong> 1.34 ms | <strong>Cloud Egress:</strong> ZERO KB (Saved 100% WAN bandwidth)</p>
          <div class="hinglish-note" style="margin-top:12px; padding:10px 14px; background:rgba(16,185,129,0.1); border-left:3px solid #10B981; border-radius:0 6px 6px 0; color:#A7F3D0; font-size:0.9rem;">
            🗣️ <strong>Hinglish Me Samjho:</strong> Yeh ek clean software tha. Score sirf 0.0341 aaya (&le; 0.10). Agent ne bina cloud ko pareshan kiye 1.34 millisecond me pass kar diya. Workstation par 0% lag aaya!
          </div>
          <p class="outcome-note">✓ Process passed immediately into user workspace. Zero disruption to user experience.</p>
        </div>
      `;
    } else if (scenario === 'malware') {
      resultBox.innerHTML = `
        <div class="sim-outcome-card kill">
          <div class="outcome-badge kill">VERDICT: LOCAL TERMINATE (< 2ms)</div>
          <h4>Process: ransomware_dropper.exe (PID: 284102)</h4>
          <p><strong>Tier 1 Score:</strong> 0.9742 (Threshold &ge; 0.90)</p>
          <p><strong>Response Latency:</strong> 1.62 ms | <strong>Action:</strong> Win32 TerminateProcess API invoked</p>
          <p><strong>Forensic Flags:</strong> 48 DLL image loads within 50ms burst + AppData\\Local\\Temp launch.</p>
          <div class="hinglish-note" style="margin-top:12px; padding:10px 14px; background:rgba(244,63,94,0.1); border-left:3px solid #F43F5E; border-radius:0 6px 6px 0; color:#FECDD3; font-size:0.9rem;">
            🗣️ <strong>Hinglish Me Samjho:</strong> Yeh pakka ransomware dropper tha! Score 0.9742 aaya (&ge; 0.90). Tier 1 ne bina cloud ke reply ka intezar kiye 1.62ms me process ko jaan se maar diya taaki ek bhi file encrypt na ho sake!
          </div>
          <p class="outcome-note">🚨 Neutralized on the spot before network sockets opened or file encryption began.</p>
        </div>
      `;
    } else { // grey_zone
      resultBox.innerHTML = `
        <div class="sim-outcome-card grey">
          <div class="outcome-badge grey">VERDICT: CLOUD ESCALATION & KILL</div>
          <h4>Process: powershell_stealth.exe (PID: 291404)</h4>
          <p><strong>Tier 1 Score:</strong> 0.6800 (Grey Zone: 0.10 &ndash; 0.90) &rarr; Dispatched to Cloud Tier 2 (Port 8000)</p>
          <p><strong>Tier 2 ResNet Confidence:</strong> 0.8845 (Optimal Threshold &Theta; = 0.6546)</p>
          <div class="xai-mini-table">
            <strong>Integrated Gradients XAI Attribution:</strong>
            <ul>
              <li>cmd_has_base64: <span style="color:#FF1744; font-weight:bold;">+0.312</span></li>
              <li>is_executing_from_temp: <span style="color:#FF1744; font-weight:bold;">+0.245</span></li>
              <li>outbound_socket_burst: <span style="color:#FF1744; font-weight:bold;">+0.141</span></li>
            </ul>
          </div>
          <div class="hinglish-note" style="margin-top:12px; padding:10px 14px; background:rgba(245,158,11,0.1); border-left:3px solid #F59E0B; border-radius:0 6px 6px 0; color:#FDE68A; font-size:0.9rem;">
            🗣️ <strong>Hinglish Me Samjho:</strong> Yeh script bohot shani ban rahi thi (encoded PowerShell). Tier 1 ko shak hua (Score 0.68), isne jaldbaazi me band karne ke bajaye Cloud ResNet ko bheja. Cloud ne Base64 aur Temp execution dekh kar 0.8845 score diya aur kill order de diya!
          </div>
          <p class="outcome-note">🛡️ Directive returned: Process terminated, binary vaulted, C2 IP blacklisted.</p>
        </div>
      `;
    }
  }

  // 7. Expand / Collapse All for Grilling Section
  window.toggleAllQuestions = function() {
    const items = document.querySelectorAll(".accordion-item");
    const anyClosed = Array.from(items).some(item => !item.classList.contains("open"));
    items.forEach(item => {
      if (anyClosed) {
        item.classList.add("open");
      } else {
        item.classList.remove("open");
      }
    });
  };
});
