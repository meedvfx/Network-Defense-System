import os
import tempfile
import textwrap
import re
from fpdf import FPDF

class NDS_PDF(FPDF):
    def header(self):
        # Times bold 16
        self.set_font('times', 'B', 16)
        # Move to the right
        self.cell(80)
        # Title
        self.cell(30, 10, 'Network Defense System - SOC Report', 0, 0, 'C')
        # Line break
        self.ln(20)

    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        # Times italic 10
        self.set_font('times', 'I', 10)
        # Page number
        self.cell(0, 10, 'Page ' + str(self.page_no()) + '/{nb}', 0, 0, 'C')


def create_pdf_from_markdown(md_text: str) -> str:
    """
    Convertit un markdown en PDF de façon rudimentaire avec fpdf2.
    Sauvegarde le fichier temporairement et retourne son chemin absolu.
    
    Note: fpdf2 n'a pas un parseur markdown complet, donc on va faire une conversion 
    simplifiée ou utiliser écrire du texte planifié. On nettoie juste le Markdown de base.
    """
    pdf = NDS_PDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # L'idéal serait d'utiliser weasyprint ou wkhtmltopdf pour un vrai rendu,
    # mais pour une dépendance légère pure Python on le fait à la main.
    
    lines = md_text.split('\n')
    
    for line in lines:
        line_clean = line.strip()
        if not line_clean:
            pdf.ln(5)
            continue
            
        # Helper pour écrire des lignes emballées de manière sûre
        def safe_write(text_content, font_style, font_size, indent=0, bold=False):
            self_font = 'times'
            pdf.set_font(self_font, 'B' if bold else font_style, font_size)
            if indent > 0:
                pdf.set_x(10 + indent)
            # Largeur max ajustée selon l'indentation (Times prend un peu plus ou moins de place)
            max_width = 75 if indent > 0 else 85
            wrapped = textwrap.wrap(text_content, width=max_width)
            for wl in wrapped:
                # h=7 pour taille 12
                pdf.cell(w=0, h=7, txt=wl, ln=1)
                if indent > 0:
                    pdf.set_x(10 + indent)

        txt_size = 12
        title_size = 16
        sub_size = 14

        if line_clean.startswith('### '):
            pdf.ln(2)
            safe_write(line_clean[4:], '', sub_size, bold=True)
            pdf.ln(1)
        elif line_clean.startswith('## '):
            pdf.ln(3)
            safe_write(line_clean[3:], '', title_size, bold=True)
            pdf.ln(2)
        elif line_clean.startswith('# '):
            pdf.ln(4)
            safe_write(line_clean[2:], '', title_size + 2, bold=True)
            pdf.ln(2)
        elif line_clean.startswith('- ') or line_clean.startswith('* '):
            # Force un seul tiret même si le LLM a généré "- - "
            txt = re.sub(r'^[-*]\s+([-*]\s+)*', '- ', line_clean)
            txt = re.sub(r'[*_]', '', txt)
            safe_write(txt, '', txt_size, indent=5)
        elif line_clean.startswith('> '):
            txt = re.sub(r'[*_]', '', line_clean[2:])
            safe_write(txt, 'I', txt_size, indent=10)
        else:
            # Traitement des titres gras de paragraphe (ex: **Threat Index**) ou items de liste (1. **)
            txt = line_clean
            if line_clean.startswith('**') and line_clean.endswith('**'):
                safe_write(line_clean.replace('**', ''), '', txt_size, bold=True)
            elif re.match(r'^\d+\.\s+\*\*', line_clean):
                 # Handle "1. **IP**" format
                 safe_write(re.sub(r'[*_]', '', line_clean), '', txt_size, indent=5)
            else:
                clean_txt = re.sub(r'[*_]', '', line_clean)
                safe_write(clean_txt, '', txt_size)
            
    # Sauvegarde sur un chemin temporaire
    fd, temp_path = tempfile.mkstemp(suffix='.pdf', prefix='nds_report_')
    os.close(fd)
    
    # Fpdf2 output supporte l'enregistrement de fichier optionnel via dest
    # mais FPDF2.x demande en général juste la chaîne du chemin de fichier en premier argument
    # si fname n'est pas reconnu c'est peut-être FPDF 1.7.2 pip installé.
    # Essayons pdf.output(temp_path) pour fpdf2
    pdf.output(temp_path)
    
    return temp_path
