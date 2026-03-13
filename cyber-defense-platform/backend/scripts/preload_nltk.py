import nltk

def preload():
    print("Preloading NLTK data...")
    resources = ['vader_lexicon', 'punkt', 'stopwords']
    for res in resources:
        try:
            print(f"Downloading {res}...")
            nltk.download(res, quiet=False)
        except Exception as e:
            print(f"Error downloading {res}: {e}")
    print("Preload complete!")

if __name__ == "__main__":
    preload()
