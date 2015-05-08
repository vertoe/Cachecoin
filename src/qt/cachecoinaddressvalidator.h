#ifndef CACHECOINADDRESSVALIDATOR_H
#define CACHECOINADDRESSVALIDATOR_H

#include <QRegExpValidator>

/** Base48 entry widget validator.
   Corrects near-miss characters and refuses characters that are no part of base48.
 */
class CachecoinAddressValidator : public QValidator
{
    Q_OBJECT
public:
    explicit CachecoinAddressValidator(QObject *parent = 0);

    State validate(QString &input, int &pos) const;

    static const int MaxAddressLength = 35;
signals:

public slots:

};

#endif // CACHECOINADDRESSVALIDATOR_H
