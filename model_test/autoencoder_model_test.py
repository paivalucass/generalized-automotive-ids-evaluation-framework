import torch
from torch.utils.data import DataLoader, TensorDataset
from torch import nn
import numpy as np
import typing
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

class PytorchAutoencoderTest:

    def __init__(self, model: nn.Module, batch_size: int, percentile: float = 99.5):
        self.model = model
        self.batch_size = batch_size
        self.percentile = percentile
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)

    def compute_reconstruction_errors(self, dataloader: DataLoader) -> typing.Tuple[np.ndarray, np.ndarray]:
        """Calcula o erro de reconstrução MSE e extrai rótulos y_true."""
        self.model.eval()
        errors, labels = [], []
        with torch.no_grad():
            for data, target in dataloader:
                # Normalização (apenas X)
                data = data.float().to(self.device) / 15.0
                
                out = self.model(data)
                recon = out[0] if isinstance(out, (tuple, list)) else out
                
                # Erro MSE por amostra
                batch_errors = torch.mean(
                    (recon - data) ** 2,
                    dim=tuple(range(1, recon.dim()))
                ).cpu().numpy()
                
                errors.extend(batch_errors.tolist())
                labels.extend(target.cpu().numpy())
                
        return np.array(errors), np.array(labels)

    def __compute_threshold(self, errors_train: np.ndarray):
        """Calcula o limiar de anomalia usando o percentil."""
        thr = np.percentile(errors_train, self.percentile)
        print(f"→ Limiar (Threshold) de Anomalia usando Percentil {self.percentile}: {thr:.6f}")
        return thr

    def execute(self, test_data: typing.List[typing.Tuple[np.ndarray, int]], errors_train: np.ndarray):
        """
        test_data: Lista de (x, y) pares (y = 0 normal, 1 anomalia)
        errors_train: Erros de reconstrução do conjunto de treinamento normal.
        """
        # Preparação do DataLoader
        test_X = torch.stack([torch.tensor(d[0], dtype=torch.float) for d in test_data])
        test_Y = torch.tensor([d[1] for d in test_data], dtype=torch.int)
        dataset = TensorDataset(test_X, test_Y)
        testloader = DataLoader(dataset, batch_size=self.batch_size, shuffle=False)

        # 1. Calcular o Threshold a partir dos erros de treino
        threshold = self.__compute_threshold(errors_train)
        
        # 2. Calcular erros de reconstrução e rótulos no conjunto de teste
        errors_test, y_true = self.compute_reconstruction_errors(testloader)
        
        # 3. Classificação: Anomalia se Erro > Threshold
        y_pred = (errors_test > threshold).astype(int) # 1 = Anomalia

        # 4. Cálculo das Métricas
        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        conf_matrix = confusion_matrix(y_true, y_pred)
        
        print("\n--- Resultados de Teste ---")
        print(f"Acurácia: {acc:.4f}")
        print(f"Precisão: {prec:.4f}")
        print(f"Recall:   {recall:.4f}")
        print(f"F1-Score: {f1:.4f}")
        print("\nMatriz de Confusão (True/Predicted):")
        print(conf_matrix)
        
        # Salvar resultados (opcional, mas bom para depuração)
        np.save("y_true_test.npy", y_true)
        np.save("y_pred_test.npy", y_pred)
        np.save("errors_test.npy", errors_test)