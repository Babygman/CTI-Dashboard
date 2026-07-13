USE CTIDashboard;
GO

CREATE TABLE Vendors
(
    VendorId INT IDENTITY(1,1) PRIMARY KEY,

    VendorName NVARCHAR(100) NOT NULL,

    Category NVARCHAR(100),

    Website NVARCHAR(255),

    Enabled BIT DEFAULT 1
);
GO