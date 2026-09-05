content = open("/home/kali/asvs-pro/server.py").read()

new_pdf = '''@app.route('/api/export/pdf', methods=['POST'])
def export_pdf():
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
        from reportlab.lib.units import cm
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
        from reportlab.platypus import Image as RLImage
        import datetime

        data = request.json
        results = data.get('categoryResults', {})
        project = data.get('project_name', 'ASVS Analysis')
        buf = io.BytesIO()

        doc = SimpleDocTemplate(
            buf, pagesize=A4,
            topMargin=1.5*cm, bottomMargin=2*cm,
            leftMargin=2*cm, rightMargin=2*cm,
            title=f"ASVS Report — {project}",
            author="ASVS Analyzer Pro"
        )

        # ── Styles ────────────────────────────────────────────────
        navy   = colors.HexColor("#1F3864")
        blue   = colors.HexColor("#2E4B8E")
        green  = colors.HexColor("#276221")
        red    = colors.HexColor("#9C0006")
        amber  = colors.HexColor("#9C6500")
        light  = colors.HexColor("#EEF4FF")
        white  = colors.white
        gray   = colors.HexColor("#7F7F7F")
        lgray  = colors.HexColor("#F5F5F5")

        title_s = ParagraphStyle("title", fontSize=22, fontName="Helvetica-Bold",
                                 textColor=white, alignment=TA_CENTER, spaceAfter=4, leading=28)
        sub_s   = ParagraphStyle("sub", fontSize=11, fontName="Helvetica",
                                 textColor=colors.HexColor("#DCE6F1"), alignment=TA_CENTER, spaceAfter=2)
        h2_s    = ParagraphStyle("h2", fontSize=13, fontName="Helvetica-Bold",
                                 textColor=navy, spaceAfter=6, spaceBefore=14,
                                 borderPad=4)
        h3_s    = ParagraphStyle("h3", fontSize=10, fontName="Helvetica-Bold",
                                 textColor=blue, spaceAfter=4, spaceBefore=8)
        body_s  = ParagraphStyle("body", fontSize=9, fontName="Helvetica",
                                 textColor=colors.HexColor("#333333"), spaceAfter=3, leading=14)
        pass_s  = ParagraphStyle("pass", fontSize=9, fontName="Helvetica-Bold",
                                 textColor=green)
        fail_s  = ParagraphStyle("fail", fontSize=9, fontName="Helvetica-Bold",
                                 textColor=red)
        small_s = ParagraphStyle("small", fontSize=8, fontName="Helvetica",
                                 textColor=gray, alignment=TA_CENTER)

        story = []

        # ── Cover Page ────────────────────────────────────────────
        # Header banner
        banner_data = [[Paragraph("ASVS Analyzer Pro", title_s)],
                       [Paragraph("Application Security Verification Standard Report", sub_s)]]
        banner = Table(banner_data, colWidths=[17*cm])
        banner.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), navy),
            ("ROUNDEDCORNERS", [8]),
            ("TOPPADDING", (0,0), (-1,-1), 18),
            ("BOTTOMPADDING", (0,0), (-1,-1), 18),
            ("LEFTPADDING", (0,0), (-1,-1), 20),
            ("RIGHTPADDING", (0,0), (-1,-1), 20),
        ]))
        story.append(banner)
        story.append(Spacer(1, 0.5*cm))

        # Meta info table
        now = datetime.datetime.now().strftime("%d %B %Y  %H:%M")
        total_found = sum(cd.get("implemented",0) for cd in results.values())
        total_reqs  = sum(cd.get("total",0) for cd in results.values())
        overall     = round((total_found/total_reqs)*100) if total_reqs else 0
        lvl         = "Level 2" if overall >= 70 else "Level 1" if overall >= 40 else "Below Level 1"
        lvl_color   = green if overall >= 70 else amber if overall >= 40 else red

        meta = [
            ["Project", project],
            ["Report Date", now],
            ["Standard", "OWASP ASVS 5.0"],
            ["Tool", "ASVS Analyzer Pro"],
            ["Overall Coverage", f"{overall}%"],
            ["Maturity Level", lvl],
        ]
        meta_style = ParagraphStyle("meta", fontSize=10, fontName="Helvetica")
        meta_bold  = ParagraphStyle("metab", fontSize=10, fontName="Helvetica-Bold", textColor=navy)

        meta_table_data = [[Paragraph(k, meta_bold), Paragraph(v, meta_style)] for k,v in meta]
        meta_table = Table(meta_table_data, colWidths=[5*cm, 12*cm])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (0,-1), light),
            ("BACKGROUND", (1,0), (1,-1), white),
            ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#CCCCCC")),
            ("TOPPADDING", (0,0), (-1,-1), 7),
            ("BOTTOMPADDING", (0,0), (-1,-1), 7),
            ("LEFTPADDING", (0,0), (-1,-1), 10),
            ("ROUNDEDCORNERS", [4]),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width="100%", thickness=2, color=navy))
        story.append(Spacer(1, 0.3*cm))

        # ── Executive Summary ─────────────────────────────────────
        story.append(Paragraph("Executive Summary", h2_s))

        # Score cards row
        cats_passed  = sum(1 for cd in results.values() if cd.get("pct",0) >= 70)
        cats_partial = sum(1 for cd in results.values() if 0 < cd.get("pct",0) < 70)
        cats_failed  = sum(1 for cd in results.values() if cd.get("pct",0) == 0)

        score_data = [
            [Paragraph(f"<b>{total_found}</b>", ParagraphStyle("sc",fontSize=20,fontName="Helvetica-Bold",textColor=blue,alignment=TA_CENTER)),
             Paragraph(f"<b>{total_reqs}</b>", ParagraphStyle("sc",fontSize=20,fontName="Helvetica-Bold",textColor=navy,alignment=TA_CENTER)),
             Paragraph(f"<b>{overall}%</b>", ParagraphStyle("sc",fontSize=20,fontName="Helvetica-Bold",textColor=lvl_color,alignment=TA_CENTER)),
             Paragraph(f"<b>{lvl}</b>", ParagraphStyle("sc",fontSize=14,fontName="Helvetica-Bold",textColor=lvl_color,alignment=TA_CENTER))],
            [Paragraph("Controls Found", small_s),
             Paragraph("Total Requirements", small_s),
             Paragraph("Coverage", small_s),
             Paragraph("Maturity Level", small_s)],
        ]
        score_table = Table(score_data, colWidths=[4*cm]*4)
        score_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), light),
            ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#CCCCCC")),
            ("TOPPADDING", (0,0), (-1,-1), 10),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("ALIGN", (0,0), (-1,-1), "CENTER"),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("ROUNDEDCORNERS", [6]),
        ]))
        story.append(score_table)
        story.append(Spacer(1, 0.4*cm))

        # ── Category Summary Table ─────────────────────────────────
        story.append(Paragraph("Category Breakdown", h2_s))

        cat_header = [
            Paragraph("<b>Security Category</b>", ParagraphStyle("th",fontSize=9,fontName="Helvetica-Bold",textColor=white,alignment=TA_CENTER)),
            Paragraph("<b>Found</b>", ParagraphStyle("th",fontSize=9,fontName="Helvetica-Bold",textColor=white,alignment=TA_CENTER)),
            Paragraph("<b>Total</b>", ParagraphStyle("th",fontSize=9,fontName="Helvetica-Bold",textColor=white,alignment=TA_CENTER)),
            Paragraph("<b>Coverage</b>", ParagraphStyle("th",fontSize=9,fontName="Helvetica-Bold",textColor=white,alignment=TA_CENTER)),
            Paragraph("<b>Status</b>", ParagraphStyle("th",fontSize=9,fontName="Helvetica-Bold",textColor=white,alignment=TA_CENTER)),
        ]
        cat_rows = [cat_header]
        cat_styles = [
            ("BACKGROUND", (0,0), (-1,0), navy),
            ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#CCCCCC")),
            ("TOPPADDING", (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING", (0,0), (-1,-1), 8),
            ("ALIGN", (1,0), (-1,-1), "CENTER"),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ]

        for i, (cat, cd) in enumerate(results.items(), 1):
            imp = cd.get("implemented",0); tot = cd.get("total",0)
            pct = round((imp/tot)*100) if tot else 0
            status = "Level 2" if pct >= 70 else "Level 1" if pct >= 40 else "Below L1"
            s_color = green if pct >= 70 else amber if pct >= 40 else red
            bg = light if i % 2 == 0 else white
            cat_rows.append([
                Paragraph(cat, body_s),
                Paragraph(str(imp), ParagraphStyle("c",fontSize=9,fontName="Helvetica",alignment=TA_CENTER)),
                Paragraph(str(tot), ParagraphStyle("c",fontSize=9,fontName="Helvetica",alignment=TA_CENTER)),
                Paragraph(f"{pct}%", ParagraphStyle("c",fontSize=9,fontName="Helvetica-Bold",alignment=TA_CENTER)),
                Paragraph(status, ParagraphStyle("s",fontSize=9,fontName="Helvetica-Bold",textColor=s_color,alignment=TA_CENTER)),
            ])
            cat_styles.append(("BACKGROUND", (0,i), (-1,i), bg))

        # Total row
        cat_rows.append([
            Paragraph("<b>TOTAL</b>", ParagraphStyle("tot",fontSize=9,fontName="Helvetica-Bold")),
            Paragraph(f"<b>{total_found}</b>", ParagraphStyle("tot",fontSize=9,fontName="Helvetica-Bold",alignment=TA_CENTER)),
            Paragraph(f"<b>{total_reqs}</b>", ParagraphStyle("tot",fontSize=9,fontName="Helvetica-Bold",alignment=TA_CENTER)),
            Paragraph(f"<b>{overall}%</b>", ParagraphStyle("tot",fontSize=9,fontName="Helvetica-Bold",alignment=TA_CENTER)),
            Paragraph("", body_s),
        ])
        cat_styles.append(("BACKGROUND", (0,len(cat_rows)-1), (-1,len(cat_rows)-1), colors.HexColor("#DCE6F1")))

        cat_table = Table(cat_rows, colWidths=[7*cm, 2.2*cm, 2.2*cm, 2.6*cm, 3*cm])
        cat_table.setStyle(TableStyle(cat_styles))
        story.append(cat_table)
        story.append(PageBreak())

        # ── Detailed Findings per Category ────────────────────────
        story.append(Paragraph("Detailed Findings", h2_s))

        for cat, cd in results.items():
            reqs = cd.get("reqs", [])
            imp  = cd.get("implemented", 0)
            tot  = cd.get("total", 0)
            pct  = round((imp/tot)*100) if tot else 0

            # Category header
            cat_banner_data = [[
                Paragraph(f"<b>{cat}</b>", ParagraphStyle("cb",fontSize=11,fontName="Helvetica-Bold",textColor=white)),
                Paragraph(f"{imp}/{tot}  ({pct}%)", ParagraphStyle("cr",fontSize=10,fontName="Helvetica",textColor=white,alignment=TA_RIGHT)),
            ]]
            cat_banner = Table(cat_banner_data, colWidths=[12*cm, 5*cm])
            cat_banner.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,-1), blue),
                ("TOPPADDING", (0,0), (-1,-1), 8),
                ("BOTTOMPADDING", (0,0), (-1,-1), 8),
                ("LEFTPADDING", (0,0), (0,-1), 12),
                ("RIGHTPADDING", (-1,0), (-1,-1), 12),
                ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
                ("ROUNDEDCORNERS", [4]),
            ]))
            story.append(cat_banner)
            story.append(Spacer(1, 0.2*cm))

            # Requirements table
            req_header = [
                Paragraph("<b>ID</b>", ParagraphStyle("rh",fontSize=8,fontName="Helvetica-Bold",textColor=white,alignment=TA_CENTER)),
                Paragraph("<b>L</b>", ParagraphStyle("rh",fontSize=8,fontName="Helvetica-Bold",textColor=white,alignment=TA_CENTER)),
                Paragraph("<b>Verification Requirement</b>", ParagraphStyle("rh",fontSize=8,fontName="Helvetica-Bold",textColor=white)),
                Paragraph("<b>Status</b>", ParagraphStyle("rh",fontSize=8,fontName="Helvetica-Bold",textColor=white,alignment=TA_CENTER)),
                Paragraph("<b>Finding</b>", ParagraphStyle("rh",fontSize=8,fontName="Helvetica-Bold",textColor=white)),
            ]
            req_rows = [req_header]
            req_styles = [
                ("BACKGROUND", (0,0), (-1,0), navy),
                ("GRID", (0,0), (-1,-1), 0.4, colors.HexColor("#CCCCCC")),
                ("TOPPADDING", (0,0), (-1,-1), 5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ("LEFTPADDING", (0,0), (-1,-1), 6),
                ("ALIGN", (0,0), (1,-1), "CENTER"),
                ("ALIGN", (3,0), (3,-1), "CENTER"),
                ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ]

            for i, req in enumerate(reqs, 1):
                implemented = req.get("implemented", False)
                status_txt  = "Pass" if implemented else "Fail"
                s_col = green if implemented else red
                finding_txt = req.get("finding",{}).get("note","") if req.get("finding") else "Not detected — manual review required"
                bg = light if i % 2 == 0 else white

                req_rows.append([
                    Paragraph(req.get("id",""), ParagraphStyle("ri",fontSize=8,fontName="Helvetica-Bold",textColor=blue,alignment=TA_CENTER)),
                    Paragraph(req.get("level",""), ParagraphStyle("rl",fontSize=8,fontName="Helvetica",alignment=TA_CENTER)),
                    Paragraph(req.get("requirement","")[:200], ParagraphStyle("rr",fontSize=8,fontName="Helvetica",leading=11)),
                    Paragraph(f"<b>{status_txt}</b>", ParagraphStyle("rs",fontSize=8,fontName="Helvetica-Bold",textColor=s_col,alignment=TA_CENTER)),
                    Paragraph(finding_txt[:120], ParagraphStyle("rf",fontSize=7,fontName="Helvetica",textColor=gray,leading=10)),
                ])
                req_styles.append(("BACKGROUND", (0,i), (-1,i), bg))
                if implemented:
                    req_styles.append(("BACKGROUND", (3,i), (3,i), colors.HexColor("#C6EFCE")))
                else:
                    req_styles.append(("BACKGROUND", (3,i), (3,i), colors.HexColor("#FFC7CE")))

            req_table = Table(req_rows, colWidths=[1.5*cm, 0.8*cm, 7.5*cm, 1.5*cm, 5.7*cm])
            req_table.setStyle(TableStyle(req_styles))
            story.append(req_table)
            story.append(Spacer(1, 0.4*cm))

        # ── Footer note ───────────────────────────────────────────
        story.append(HRFlowable(width="100%", thickness=1, color=navy))
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph(
            "This report was generated automatically by ASVS Analyzer Pro. "
            "Coverage percentages indicate pattern-based detection coverage and are intended as a "
            "security maturity indicator, not a formal compliance certification. "
            "Manual review is recommended for complete ASVS compliance verification.",
            ParagraphStyle("footer",fontSize=7,fontName="Helvetica",textColor=gray,alignment=TA_CENTER,leading=10)
        ))

        doc.build(story)
        buf.seek(0)
        return send_file(buf, mimetype="application/pdf",
                         as_attachment=True, download_name="ASVS-Pro-Report.pdf")
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500'''

start = content.find("@app.route('/api/export/pdf'")
end = content.find("\nif __name__")
if start != -1 and end != -1:
    new_content = content[:start] + new_pdf + "\n" + content[end:]
    open("/home/kali/asvs-pro/server.py", "w").write(new_content)
    print("PDF export fixed!")
else:
    print("ERROR: Could not find pdf function")
