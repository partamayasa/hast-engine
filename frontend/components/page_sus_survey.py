# frontend/components/page_sus_survey.py
"""
Modul Kuesioner System Usability Scale (SUS).
Antarmuka survei khusus yang diakses responden melalui URL: ?page=sus
Berdasarkan instrumen skala usabilitas standar internasional dari John Brooke (1986).
"""
import streamlit as st
from frontend.utils.api_client import ApiError, submit_sus


def render_page_sus_survey():
    """Menampilkan formulir kuesioner SUS mandiri untuk responden."""
    st.title("Kuesioner Evaluasi Ketergunaan Sistem")
    st.subheader("System Usability Scale (SUS)")
    st.write(
        "Instrumen pengujian ketergunaan formal berbasis standar baku **John Brooke (1986)** "
        "guna mengevaluasi **Model Penilaian Kerentanan Terintegrasi HAST (CVSS v4.0 & XAI-SHAP)**."
    )

    with st.expander("Petunjuk Pengisian Kuesioner", expanded=True):
        st.markdown(
            "1. Kuesioner ini terdiri dari **10 butir pernyataan baku** yang berselang-seling antara pernyataan bernada positif (ganjil) dan negatif (genap).\n"
            "2. Berikan penilaian yang paling mencerminkan persepsi dan pengalaman Anda setelah menguji atau mengamati artefak sistem ini.\n"
            "3. Pilihan skala penilaian:\n"
            "   * **1 = Sangat Tidak Setuju (STS)**\n"
            "   * **2 = Tidak Setuju (TS)**\n"
            "   * **3 = Netral (N)**\n"
            "   * **4 = Setuju (S)**\n"
            "   * **5 = Sangat Setuju (SS)**\n"
            "4. Seluruh data identitas dan respon yang Anda berikan dijamin kerahasiaannya dan hanya digunakan untuk keperluan akademis riset tugas akhir / tesis."
        )

    st.markdown("---")

    # Bagian identitas responden
    st.subheader("Bagian I: Identitas Responden")
    col_name, col_prof = st.columns(2)
    with col_name:
        resp_name = st.text_input(
            "Nama Lengkap atau Inisial Responden:",
            placeholder="Contoh: Budi Santoso atau R06",
            key="sus_name_input"
        )
    with col_prof:
        profession = st.selectbox(
            "Profesi / Bidang Keahlian Anda:",
            [
                "Cybersecurity Analyst",
                "Penetration Tester",
                "Software Engineer / Developer",
                "Akademisi / Dosen TI",
                "Mahasiswa Pascasarjana",
                "Peneliti Keamanan Siber",
                "Praktisi IT / Lainnya"
            ],
            key="sus_prof_input"
        )

    st.markdown("---")

    # Bagian 10 pernyataan standar SUS
    st.subheader("Bagian II: Butir Pernyataan Ketergunaan Sistem")

    questions = [
        ("q1", "1. Saya berpikir akan sering menggunakan aplikasi sistem penilaian kerentanan terintegrasi (HAST) ini dalam aktivitas analisis keamanan siber."),
        ("q2", "2. Saya merasa antarmuka dan alur kerja aplikasi ini terlalu rumit untuk digunakan."),
        ("q3", "3. Saya merasa antarmuka dashboard aplikasi ini mudah dipahami dan digunakan."),
        ("q4", "4. Saya merasa memerlukan bantuan tenaga ahli teknis untuk dapat mengoperasikan aplikasi ini secara optimal."),
        ("q5", "5. Saya menemukan bahwa berbagai fitur penilaian (SAST, DAST, Korelasi Hibrida, XAI-SHAP) terintegrasi dengan sangat baik di dalam sistem ini."),
        ("q6", "6. Saya merasa terdapat terlalu banyak inkonsistensi pada sistem aplikasi ini (misal: navigasi atau tampilan antarmuka)."),
        ("q7", "7. Saya yakin sebagian besar profesional keamanan siber atau analis kerentanan dapat mempelajari dan menguasai aplikasi ini dengan cepat."),
        ("q8", "8. Saya merasa proses pengoperasian aplikasi ini sangat membingungkan dan melelahkan."),
        ("q9", "9. Saya merasa sangat percaya diri dan terbantu dalam mengambil keputusan remediasi celah keamanan saat menggunakan aplikasi ini."),
        ("q10", "10. Saya merasa harus mempelajari banyak hal baru sebelum saya dapat mulai menggunakan aplikasi ini dengan lancar.")
    ]

    scale_options = [
        (1, "1 - Sangat Tidak Setuju (STS)"),
        (2, "2 - Tidak Setuju (TS)"),
        (3, "3 - Netral (N)"),
        (4, "4 - Setuju (S)"),
        (5, "5 - Sangat Setuju (SS)")
    ]

    answers = {}

    for q_key, q_text in questions:
        st.markdown(f"**{q_text}**")
        selected_val = st.radio(
            label=q_text,
            options=[opt[0] for opt in scale_options],
            format_func=lambda x: dict(scale_options).get(x, str(x)),
            index=2,  # Bawaan: Netral (3)
            horizontal=True,
            key=f"sus_{q_key}",
            label_visibility="collapsed"
        )
        answers[q_key] = selected_val
        st.markdown("<div style='margin-bottom: 12px;'></div>", unsafe_allow_html=True)

    st.markdown("---")

    submitted = st.button("Kirim Penilaian Ketergunaan (Submit SUS)", type="primary", use_container_width=True)
    st.caption("* Setelah dikirim, skor SUS individual Anda akan dikalkulasi secara otomatis berdasarkan formula John Brooke (1986).")

    if submitted:
        if not resp_name.strip():
            st.error("Nama atau inisial responden wajib diisi sebelum mengirimkan penilaian.")
        else:
            try:
                res = submit_sus(resp_name, profession, answers)
            except ApiError as e:
                st.error(f"Penilaian gagal dikirim: {e}")
                st.stop()
            new_id, raw_s, sus_s = res["id"], res["raw_score"], res["sus_score"]
            acc, grade = res["acceptability"], res["grade_scale"]

            st.success(
                f"Terima kasih atas partisipasi Anda, {resp_name}! Penilaian Anda telah berhasil direkam (ID Respon: #{new_id})."
            )

            c_res1, c_res2, c_res3, c_res4 = st.columns(4)
            c_res1.metric("Skor Mentah", f"{raw_s} / 40")
            c_res2.metric("Skor SUS Anda", f"{sus_s} / 100")
            c_res3.metric("Tingkat Penerimaan", acc)
            c_res4.metric("Predikat Kualitatif", grade)

            st.info(
                "Data evaluasi Anda telah masuk ke dalam rekapitulasi riset tesis secara otomatis. Anda dapat menutup halaman ini atau kembali ke aplikasi utama."
            )

    st.markdown("---")
    st.markdown(
        "<div style='text-align: center;'><a href='/' target='_self' style='text-decoration: none; color: #0984e3; font-weight: 500;'>Kembali ke Halaman Utama Aplikasi</a></div>",
        unsafe_allow_html=True
    )

