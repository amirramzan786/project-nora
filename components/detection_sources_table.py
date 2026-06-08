import streamlit.components.v1 as components


def render_detection_sources_table(
    detection_sources_df,
    estimated_confidence
):

    table_html = """
    <div class='nora-intel-table'>
        <div class='nora-intel-table-header'>
            <div>Source IP</div>
            <div>Behaviour</div>
            <div>Region</div>
            <div>Similarity</div>
            <div>Confidence</div>
        </div>
    """

    for _, row in detection_sources_df.iterrows():

        similarity = str(
            row.get("Similarity", "0%")
        )

        confidence = str(
            row.get(
                "Confidence",
                f"{estimated_confidence}%"
            )
        )

        table_html += f"""
        <div class='nora-intel-table-row'>
            <div>{row.get('Threat Source', 'N/A')}</div>
            <div>{row.get('Threat Class', 'Behavioural Activity')}</div>
            <div>{row.get('Region', 'Unknown')}</div>
            <div>
                <span class='nora-intel-pill nora-intel-pill-blue'>
                    {similarity}
                </span>
            </div>
            <div>
                <span class='nora-intel-pill nora-intel-pill-purple'>
                    {confidence}
                </span>
            </div>
        </div>
        """

    table_html += "</div>"

    components.html(
        f"""
        <style>
        body {{
            margin: 0;
            background: transparent;
            color: #f8fafc;
            font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }}

        .nora-intel-table {{
            width: 100%;
            border: 1px solid rgba(80,120,180,0.25);
            border-radius: 14px;
            overflow: hidden;
            background:
                radial-gradient(circle at 10% 15%, rgba(56,189,248,0.06), transparent 35%),
                radial-gradient(circle at 90% 85%, rgba(37,99,235,0.08), transparent 45%),
                rgba(5,12,24,0.82);
            box-shadow:
                0 12px 30px rgba(0,0,0,0.25),
                inset 0 1px 0 rgba(255,255,255,0.03);
        }}

        .nora-intel-table-header,
        .nora-intel-table-row {{
            display: grid;
            grid-template-columns: 1.2fr 2fr 1fr 0.8fr 0.8fr;
            align-items: center;
            gap: 12px;
        }}

        .nora-intel-table-header {{
            background: rgba(20,30,50,0.95);
            color: #aeb7c8;
            font-weight: 700;
            padding: 14px 18px;
            font-size: 14px;
        }}

        .nora-intel-table-row {{
            padding: 14px 18px;
            border-top: 1px solid rgba(80,120,180,0.15);
            font-size: 14px;
            font-weight: 600;
        }}

        .nora-intel-table-row:hover {{
            background: rgba(40,80,140,0.08);
        }}

        .nora-intel-pill {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 52px;
            padding: 4px 10px;
            border-radius: 999px;
            font-size: 13px;
            font-weight: 700;
        }}

        .nora-intel-pill-blue {{
            background: rgba(0,180,255,0.15);
            color: #59d5ff;
            border: 1px solid rgba(89,213,255,0.25);
        }}

        .nora-intel-pill-purple {{
            background: rgba(180,120,255,0.15);
            color: #c98cff;
            border: 1px solid rgba(201,140,255,0.25);
        }}
        </style>
        {table_html}
        """,
        height=330,
        scrolling=False
    )